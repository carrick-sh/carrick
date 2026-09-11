#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::dispatch::dispatcher::FsCrossSubsystem;

fn two_namespaced_roots_for_async_owner() -> (
    Arc<crate::kernel::Kernel>,
    crate::kernel::KernelContext,
    crate::kernel::KernelContext,
) {
    use carrick_kernel::arena::KernelArena;

    use crate::kernel::{Container, LaunchContext, RootBootstrap, RunId};
    use crate::namespace::pid::NsSharedRegion;

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let alpha = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "fasync-alpha",
    ))));
    alpha
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("alpha pid namespace"))
        .expect("install alpha pid namespace");
    let alpha_bootstrap = RootBootstrap::for_reference_model(
        4_710,
        carrick_hal::ThreadId::synthetic_for_tests(4_710),
        "fasync-alpha-init".to_owned(),
    )
    .expect("alpha bootstrap")
    .with_container(alpha);
    let (kernel, alpha) =
        crate::kernel::Kernel::bootstrap_root(alpha_bootstrap).expect("publish alpha root");

    let beta = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "fasync-beta",
    ))));
    beta.install_pid_ns(NsSharedRegion::allocate(arena).expect("beta pid namespace"))
        .expect("install beta pid namespace");
    let beta = kernel
        .prepare_container_root(
            carrick_hal::ThreadId::synthetic_for_tests(4_720),
            None,
            "fasync-beta-init".to_owned(),
            beta,
            None,
        )
        .expect("prepare beta root")
        .commit()
        .expect("publish beta root");
    (kernel, alpha, beta)
}

#[test]
fn async_process_owner_is_bound_to_the_exact_container_generation() {
    let (_kernel, alpha, beta) = two_namespaced_roots_for_async_owner();
    let alpha_owner =
        crate::kernel::objects::CapturedAsyncIoOwner::capture(&alpha, LINUX_F_OWNER_PID, 1);
    let beta_owner =
        crate::kernel::objects::CapturedAsyncIoOwner::capture(&beta, LINUX_F_OWNER_PID, 1);
    assert_eq!(alpha_owner.visible.owner_pid, 1);
    assert_eq!(beta_owner.visible.owner_pid, 1);
    let signal =
        crate::kernel::LinuxSignal::for_signal_number(LINUX_SIGIO).expect("valid async signal");
    let info = carrick_abi::LinuxSiginfo::sigpoll(LINUX_SIGIO, carrick_abi::LINUX_POLL_MSG, 0, 7);

    assert!(alpha_owner.post_kernel_signal(alpha.kernel(), signal, Some(info)));
    assert!(
        alpha
            .shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO)
    );
    assert!(
        !beta
            .shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO),
        "the other container's visible PID 1 must not receive alpha's event",
    );

    assert!(beta_owner.post_kernel_signal(beta.kernel(), signal, Some(info)));
    assert!(
        beta.shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO)
    );
}

#[test]
fn async_thread_owner_is_bound_to_the_exact_container_generation() {
    let (_kernel, alpha, beta) = two_namespaced_roots_for_async_owner();
    let alpha_owner =
        crate::kernel::objects::CapturedAsyncIoOwner::capture(&alpha, LINUX_F_OWNER_TID, 1);
    let signal =
        crate::kernel::LinuxSignal::for_signal_number(LINUX_SIGIO).expect("valid async signal");

    assert!(alpha_owner.post_kernel_signal(alpha.kernel(), signal, None));
    assert!(
        alpha
            .thread()
            .signal_state()
            .pending()
            .contains(LINUX_SIGIO)
    );
    assert!(
        !beta.thread().signal_state().pending().contains(LINUX_SIGIO),
        "the other container's visible TID 1 must not receive alpha's event",
    );
    assert!(
        !alpha
            .shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO),
        "F_OWNER_TID must not degrade to process-directed delivery",
    );
}

#[test]
fn async_owner_never_follows_a_reused_internal_pid() {
    let (kernel, alpha, _beta) = two_namespaced_roots_for_async_owner();
    let root_binding = alpha.task_binding();
    let root_tid = alpha.thread().key().tid;
    let plan = crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
        .expect("fork plan");
    let child_a = kernel
        .reserve_fork(&alpha, plan, "fasync-child-a".to_owned(), None)
        .expect("reserve child A")
        .prepare_reference(carrick_hal::ThreadId::synthetic_for_tests(4_731))
        .expect("prepare child A")
        .commit()
        .expect("publish child A")
        .into_parts()
        .expect("start child A")
        .0;
    let child_a_key = child_a.task().key();
    let owner = crate::kernel::objects::CapturedAsyncIoOwner::capture(&alpha, LINUX_F_OWNER_PID, 2);

    kernel
        .exit_task_key_eventually(
            child_a_key,
            crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
        )
        .expect("exit child A");
    drop(child_a);
    assert!(matches!(
        kernel.wait_child(
            alpha.task().key().id,
            Some(child_a_key.id),
            crate::kernel::WaitMode::Consume,
        ),
        Ok(crate::kernel::WaitOutcome::Exited(_))
    ));
    kernel.sweep_retired_threads();
    kernel.ids().set_next_for_tests(child_a_key.id.raw());

    let alpha = root_binding.capture(root_tid).expect("fresh root context");
    let child_b = kernel
        .reserve_fork(&alpha, plan, "fasync-child-b".to_owned(), None)
        .expect("reserve child B")
        .prepare_reference(carrick_hal::ThreadId::synthetic_for_tests(4_732))
        .expect("prepare child B")
        .commit()
        .expect("publish child B")
        .into_parts()
        .expect("start child B")
        .0;
    assert_eq!(child_b.task().key().id, child_a_key.id);
    assert_ne!(child_b.task().key(), child_a_key);

    let signal =
        crate::kernel::LinuxSignal::for_signal_number(LINUX_SIGIO).expect("valid async signal");
    assert!(!owner.post_kernel_signal(&kernel, signal, None));
    assert!(
        !child_b
            .shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO),
        "a late readiness event must not follow the recycled PID",
    );
}

#[test]
fn async_process_group_owner_is_bound_to_the_exact_container_generation() {
    let (_kernel, alpha, beta) = two_namespaced_roots_for_async_owner();
    let alpha_owner =
        crate::kernel::objects::CapturedAsyncIoOwner::capture(&alpha, LINUX_F_OWNER_PGRP, 1);
    let signal =
        crate::kernel::LinuxSignal::for_signal_number(LINUX_SIGIO).expect("valid async signal");

    assert!(alpha_owner.post_kernel_signal(alpha.kernel(), signal, None));
    assert!(
        alpha
            .shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO)
    );
    assert!(
        !beta
            .shared()
            .pending_signals()
            .present()
            .contains(LINUX_SIGIO),
        "the other container's visible PGID 1 must not receive alpha's event",
    );
}

#[test]
fn tiocspgrp_distinguishes_invalid_ids_from_absent_groups() {
    let (kernel, alpha, beta) = two_namespaced_roots_for_async_owner();

    assert_eq!(resolve_tiocspgrp(&alpha, -1), Err(LINUX_EINVAL));
    assert_eq!(resolve_tiocspgrp(&alpha, 0), Err(LINUX_EINVAL));
    assert_eq!(resolve_tiocspgrp(&alpha, 99), Err(LINUX_EPERM));
    assert_eq!(
        resolve_tiocspgrp(&alpha, 1),
        Ok(alpha.task().process_group())
    );
    assert_eq!(
        resolve_tiocspgrp(&beta, 1),
        Ok(beta.task().process_group()),
        "the same visible PGID resolves only in the caller's container",
    );

    let child = kernel
        .reserve_fork(
            &alpha,
            crate::kernel::ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            "tiocspgrp-foreign-session".to_owned(),
            None,
        )
        .expect("reserve session leader")
        .prepare_reference(carrick_hal::ThreadId::synthetic_for_tests(4_733))
        .expect("prepare session leader")
        .commit()
        .expect("publish session leader")
        .into_parts()
        .expect("start session leader")
        .0;
    kernel
        .create_session(child.task().key().id, None)
        .expect("create foreign session");
    let visible_group =
        crate::namespace::pid::process_group_to_ns_for(&alpha, child.task().process_group())
            .expect("foreign session group remains visible in the container");
    assert_eq!(
        resolve_tiocspgrp(
            &alpha,
            i32::try_from(visible_group).expect("visible PGID fits i32"),
        ),
        Err(LINUX_EPERM),
        "a positive PGID outside the caller's session is a permission error",
    );
}

#[test]
fn foreign_numeric_proc_pid_never_aliases_the_callers_fd_table() {
    assert_eq!(proc_self_fd_number("/proc/4242/fd/7", Some(1)), None);
    assert_eq!(
        proc_self_fdinfo_number("/proc/4242/fdinfo/7", Some(1)),
        None
    );
    assert_eq!(proc_self_magic_link("/proc/4242/exe", Some(1)), None);

    assert_eq!(proc_self_fd_number("/proc/1/fd/7", Some(1)), Some(7));
    assert_eq!(
        proc_self_fdinfo_number("/proc/1/fdinfo/7", Some(1)),
        Some(7)
    );
    assert_eq!(proc_self_magic_link("/proc/1/exe", Some(1)), Some("exe"));
}

fn logical_lock_request(
    owner: (i32, u64),
    range: (u64, u64),
    write: bool,
) -> LogicalRecordLockRequest {
    LogicalRecordLockRequest {
        file: LeaseFileId::Path("/logical-lock".to_owned()),
        owner: LogicalRecordLockOwner::Process {
            pid: owner.0,
            serial: owner.1,
        },
        range: LogicalRecordLockRange {
            start: range.0,
            end: range.1,
        },
        write,
    }
}

#[test]
fn hvpatch_classic_record_locks_conflict_by_task_generation_and_release_on_close() {
    let locks = LogicalRecordLocks::default();
    let parent = logical_lock_request((41, 1), (0, 10), true);
    let child = logical_lock_request((42, 2), (0, 10), true);

    assert_eq!(locks.try_set(parent.clone()), Ok(()));
    assert_eq!(locks.try_set(child.clone()), Err(LINUX_EAGAIN));
    let conflict = locks.conflict(&child).expect("parent conflict");
    assert_eq!(conflict.owner, parent.owner);
    assert!(conflict.write);

    locks.release_file_owner(&parent.file, parent.owner);
    assert_eq!(locks.try_set(child), Ok(()));
}

#[test]
fn hvpatch_classic_record_lock_replacement_splits_only_the_callers_range() {
    let locks = LogicalRecordLocks::default();
    let whole = logical_lock_request((41, 1), (0, 30), true);
    assert_eq!(locks.try_set(whole.clone()), Ok(()));

    locks.unlock(
        &whole.file,
        whole.owner,
        LogicalRecordLockRange { start: 10, end: 20 },
    );
    let state = locks.state.lock();
    assert_eq!(state.locks.len(), 2);
    assert_eq!(
        state.locks[0].range,
        LogicalRecordLockRange { start: 0, end: 10 }
    );
    assert_eq!(
        state.locks[1].range,
        LogicalRecordLockRange { start: 20, end: 30 }
    );
}

/// fcntl(2): "EDEADLK — It was detected that the specified F_SETLKW command
/// would cause a deadlock." LTP fcntl17 builds exactly this cycle with three
/// processes and reports `TFAIL: Alarm expired, deadlock not detected` when the
/// kernel never returns EDEADLK — carrick had no wait-for graph at all, so the
/// waiters simply parked forever and the suite TIMEOUTed.
#[test]
fn f_setlkw_cycle_reports_edeadlk_instead_of_parking_forever() {
    let locks = Arc::new(LogicalRecordLocks::default());
    let a = logical_lock_request((41, 1), (0, 10), true);
    let b = logical_lock_request((42, 1), (10, 20), true);
    assert_eq!(locks.try_set(a.clone()), Ok(()));
    assert_eq!(locks.try_set(b.clone()), Ok(()));

    // Owner A blocks waiting for B's range. Park it on a helper thread so the
    // wait-for edge is live while the main thread closes the cycle.
    let waiter = {
        let locks = Arc::clone(&locks);
        let a_wants_b = logical_lock_request((41, 1), (10, 20), true);
        std::thread::spawn(move || {
            locks
                .wait_set_interruptibly(&a_wants_b, crate::thread::ThreadId::synthetic_for_tests(1))
        })
    };
    // Wait for A's edge to appear rather than sleeping a fixed amount.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if locks.state.lock().waits_on(a.owner).is_some() {
            break;
        }
        std::thread::yield_now();
    }
    assert!(
        locks.state.lock().waits_on(a.owner).is_some(),
        "owner A should have published a wait-for edge"
    );

    // B now wants A's range: A waits on B, B would wait on A. That is a cycle.
    let b_wants_a = logical_lock_request((42, 1), (0, 10), true);
    assert_eq!(
        locks.wait_set_interruptibly(&b_wants_a, crate::thread::ThreadId::synthetic_for_tests(2)),
        Err(crate::linux_abi::LINUX_EDEADLK),
        "closing the cycle must be EDEADLK, not an unbounded park"
    );

    // Releasing B lets A through, proving the edge was retracted, not leaked.
    locks.unlock(&b.file, b.owner, b.range);
    assert_eq!(waiter.join().expect("waiter thread"), Ok(()));
    assert!(locks.state.lock().waiting_on.is_empty());
}

/// The HVPatch reactor never parks a thread in `wait_set_interruptibly`: a
/// blocked `F_SETLKW` is re-polled through `LogicalRecordLockWait::try_acquire`
/// (`try_drive_blocking_record_lock`). That poll therefore has to be the thing
/// that publishes the waiter's wait-for edge and checks for a cycle, or the
/// graph stays empty for every real guest and LTP `fcntl17` reports
/// `Alarm expired, deadlock not detected` while all three processes sit parked.
#[test]
fn reactor_polled_f_setlkw_cycle_reports_edeadlk() {
    let locks = Arc::new(LogicalRecordLocks::default());
    let a = logical_lock_request((41, 1), (0, 10), true);
    let b = logical_lock_request((42, 1), (10, 20), true);
    assert_eq!(locks.try_set(a.clone()), Ok(()));
    assert_eq!(locks.try_set(b.clone()), Ok(()));

    // A wants B's range: polled, not acquired, and its edge is now live.
    let a_wants_b = LogicalRecordLockWait::new(
        Arc::clone(&locks),
        logical_lock_request((41, 1), (10, 20), true),
        crate::thread::ThreadId::synthetic_for_tests(1),
    );
    assert_eq!(a_wants_b.try_acquire(), Err(LINUX_EAGAIN));
    assert!(
        locks.state.lock().waits_on(a.owner).is_some(),
        "a polled F_SETLKW must publish its wait-for edge"
    );

    // B wants A's range: A waits on B, B would wait on A — a cycle. The poll
    // that would close it must report EDEADLK, and must NOT leave B's edge
    // behind (B is not blocked; it got an error).
    let b_wants_a = LogicalRecordLockWait::new(
        Arc::clone(&locks),
        logical_lock_request((42, 1), (0, 10), true),
        crate::thread::ThreadId::synthetic_for_tests(2),
    );
    assert_eq!(
        b_wants_a.try_acquire(),
        Err(crate::linux_abi::LINUX_EDEADLK),
        "closing the cycle through the reactor poll must be EDEADLK"
    );
    assert!(locks.state.lock().waits_on(b.owner).is_none());

    // The verdict is per-attempt: A is still legitimately blocked, so a
    // re-poll after B's request failed is still EAGAIN, never EDEADLK.
    assert_eq!(a_wants_b.try_acquire(), Err(LINUX_EAGAIN));

    // B gives up its lock instead: A's next poll acquires and retracts its edge.
    locks.unlock(&b.file, b.owner, b.range);
    assert_eq!(a_wants_b.try_acquire(), Ok(()));
    assert!(locks.state.lock().waiting_on.is_empty());
}

/// A waiter that is abandoned without ever acquiring — the continuation is
/// torn down by EINTR, exit or exec — must retract its edge when the wait is
/// dropped, or the stale edge would convict a later, unrelated waiter of a
/// deadlock that no longer exists.
#[test]
fn dropped_reactor_record_lock_wait_retracts_its_edge() {
    let locks = Arc::new(LogicalRecordLocks::default());
    let a = logical_lock_request((41, 1), (0, 10), true);
    assert_eq!(locks.try_set(a.clone()), Ok(()));

    let b_wants_a = LogicalRecordLockWait::new(
        Arc::clone(&locks),
        logical_lock_request((42, 1), (0, 10), true),
        crate::thread::ThreadId::synthetic_for_tests(2),
    );
    assert_eq!(b_wants_a.try_acquire(), Err(LINUX_EAGAIN));
    let clone = b_wants_a.clone();
    drop(b_wants_a);
    assert!(
        locks
            .state
            .lock()
            .waits_on(LogicalRecordLockOwner::Process { pid: 42, serial: 1 })
            .is_some(),
        "a live clone of the wait keeps the edge published"
    );
    drop(clone);
    assert!(
        locks.state.lock().waiting_on.is_empty(),
        "the last handle to an abandoned wait retracts its edge"
    );

    // With B gone, A asking for what B wanted is trivially not a deadlock.
    let a_again = LogicalRecordLockWait::new(
        Arc::clone(&locks),
        logical_lock_request((41, 1), (0, 10), true),
        crate::thread::ThreadId::synthetic_for_tests(1),
    );
    assert_eq!(a_again.try_acquire(), Ok(()));
}

#[test]
fn hvpatch_blocking_classic_record_lock_wakes_after_unlock() {
    let locks = Arc::new(LogicalRecordLocks::default());
    let parent = logical_lock_request((41, 1), (0, 10), true);
    let child = logical_lock_request((42, 2), (0, 10), true);
    assert_eq!(locks.try_set(parent.clone()), Ok(()));

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker_locks = Arc::clone(&locks);
    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("publish waiter start");
        let result = worker_locks
            .wait_set_interruptibly(&child, crate::thread::ThreadId::synthetic_for_tests(42));
        done_tx.send(result).expect("publish waiter result");
    });
    started_rx.recv().expect("waiter started");
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err(),
        "conflicting F_SETLKW must remain parked"
    );

    locks.unlock(&parent.file, parent.owner, parent.range);
    assert_eq!(
        done_rx.recv_timeout(std::time::Duration::from_secs(1)),
        Ok(Ok(()))
    );
    worker.join().expect("logical record-lock waiter");
}

#[derive(Default)]
struct HostWriteEvents {
    begins: Vec<Vec<(u64, usize)>>,
    finishes: Vec<Vec<(u64, usize)>>,
}

impl GuestMemory for HostWriteEvents {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::OutOfBounds { address, length })
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })
    }

    fn begin_host_write(&mut self, ranges: &[(u64, usize)]) {
        self.begins.push(ranges.to_vec());
    }

    fn finish_host_write(&mut self, ranges: &[(u64, usize)]) {
        self.finishes.push(ranges.to_vec());
    }
}

fn fail_with_readv_host_write_guard(memory: &mut HostWriteEvents) -> Result<(), LinuxErrno> {
    let ranges = [(0x1000, 0x1000), (0x5000, 0x1000)];
    let _guard = carrick_guest_mem::HostWriteGuard::new(memory, &ranges);
    Err(LINUX_EINVAL)
}

#[test]
fn readv_host_write_guard_finishes_every_exposed_range_on_error() {
    let mut events = HostWriteEvents::default();

    assert_eq!(
        fail_with_readv_host_write_guard(&mut events),
        Err(LINUX_EINVAL)
    );

    let expected = vec![(0x1000, 0x1000), (0x5000, 0x1000)];
    assert_eq!(events.begins.as_slice(), std::slice::from_ref(&expected));
    assert_eq!(events.finishes.as_slice(), std::slice::from_ref(&expected));
}

#[test]
fn inet4_ioctl_view_uses_linux_interface_names() {
    let spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
        Some("web".to_string()),
        Vec::new(),
        Vec::new(),
    );
    let model = crate::network::model::LinuxNetworkModel::from_spec(&spec);
    let ifaces = inet4_interfaces_from_model(&model);
    let names: Vec<_> = ifaces.iter().map(|iface| iface.name.as_str()).collect();
    assert_eq!(names, ["lo", "eth0"]);
    assert_eq!(ifaces[0].addr_be, [127, 0, 0, 1]);
    assert_eq!(ifaces[1].addr_be, spec.ipv4.octets());
    assert_eq!(model.links[0].index, 1);
    assert_eq!(model.links[1].index, 2);
}

fn network_surface_model(
    name: &str,
    address: std::net::Ipv4Addr,
    flags: u32,
    mtu: u32,
) -> crate::network::model::LinuxNetworkModel {
    let mut model = crate::network::model::LinuxNetworkModel::isolated();
    let mut uplink = crate::network::model::LinuxNetworkLink::uplink(
        2,
        name.to_owned(),
        [0x02, 0, 0, 0, 0, address.octets()[3]],
    );
    uplink.flags = flags;
    uplink.mtu = mtu;
    model.links.push(uplink);
    model
        .addresses
        .push(crate::network::model::LinuxNetworkAddress::new(
            std::net::IpAddr::V4(address),
            24,
            name.to_owned(),
        ));
    model
}

fn two_roots_for_guest_network_surfaces() -> (
    Arc<crate::kernel::Kernel>,
    crate::kernel::KernelContext,
    crate::kernel::KernelContext,
) {
    use crate::kernel::{Container, LaunchContext, RootBootstrap, RunId};

    let alpha_container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "surface-alpha",
    ))));
    let alpha_bootstrap = RootBootstrap::for_reference_model(
        4_810,
        carrick_hal::ThreadId::synthetic_for_tests(4_810),
        "surface-alpha-init".to_owned(),
    )
    .expect("alpha bootstrap")
    .with_container(alpha_container);
    let (kernel, alpha) =
        crate::kernel::Kernel::bootstrap_root(alpha_bootstrap).expect("publish alpha root");

    let beta_container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "surface-beta",
    ))));
    let beta = kernel
        .prepare_container_root(
            carrick_hal::ThreadId::synthetic_for_tests(4_820),
            None,
            "surface-beta-init".to_owned(),
            beta_container,
            None,
        )
        .expect("prepare beta root")
        .commit()
        .expect("publish beta root");
    (kernel, alpha, beta)
}

fn dispatch_uname_nodename(
    dispatcher: &mut SyscallDispatcher,
    context: &crate::kernel::KernelContext,
) -> String {
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
    assert_eq!(
        dispatcher
            .dispatch(
                context,
                SyscallRequest::new(160, SyscallArgs::from([0x1000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .expect("dispatch uname"),
        DispatchOutcome::Returned { value: 0 },
    );
    let uts = memory.read_bytes(0x1000, 65 * 6).expect("read utsname");
    let nodename = &uts[65..130];
    let end = nodename
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(nodename.len());
    String::from_utf8(nodename[..end].to_vec()).expect("UTF-8 nodename")
}

fn sysfs_link_view(context: &crate::kernel::KernelContext) -> (Vec<String>, String) {
    use crate::vfs::Vfs;

    let sys = crate::vfs::SysVfs::in_namespace(context.task().net_ns());
    let names = sys
        .readdir("/sys/class/net")
        .expect("read sysfs link directory")
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    let own = context
        .task()
        .net_ns()
        .view()
        .links
        .iter()
        .find(|link| !link.loopback)
        .expect("uplink")
        .name
        .clone();
    let crate::vfs::VfsHandle::Bytes { contents, .. } = sys
        .open(
            &format!("/sys/class/net/{own}/mtu"),
            crate::vfs::OpenFlags {
                read: true,
                ..crate::vfs::OpenFlags::default()
            },
            &crate::vfs::OpenContext::default(),
        )
        .expect("open sysfs MTU")
    else {
        panic!("sysfs MTU must be a byte-backed file");
    };
    (names, String::from_utf8(contents).expect("UTF-8 sysfs MTU"))
}

fn proc_net_dev(context: &crate::kernel::KernelContext) -> String {
    use crate::vfs::Vfs;

    let network = context.task().net_ns().view();
    let open_context = crate::vfs::OpenContext {
        network_model: crate::vfs::LazyField::from_value(Some((**network).clone())),
        ..crate::vfs::OpenContext::default()
    };
    let crate::vfs::VfsHandle::Bytes { contents, .. } = crate::vfs::ProcVfs::new()
        .open(
            "/proc/net/dev",
            crate::vfs::OpenFlags {
                read: true,
                ..crate::vfs::OpenFlags::default()
            },
            &open_context,
        )
        .expect("open proc net dev")
    else {
        panic!("proc net dev must be a byte-backed file");
    };
    String::from_utf8(contents).expect("UTF-8 proc net dev")
}

fn dispatch_socket(
    dispatcher: &mut SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    domain: i32,
    socket_type: i32,
) -> i32 {
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
    let DispatchOutcome::Returned { value } = dispatcher
        .dispatch(
            context,
            SyscallRequest::new(
                198,
                SyscallArgs::from([domain as u64, socket_type as u64, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("dispatch socket")
    else {
        panic!("socket must return an fd");
    };
    i32::try_from(value).expect("socket fd")
}

fn rtnetlink_link_dump(
    dispatcher: &mut SyscallDispatcher,
    context: &crate::kernel::KernelContext,
) -> Vec<u8> {
    let fd = dispatch_socket(dispatcher, context, LINUX_AF_NETLINK, LINUX_SOCK_RAW);
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x5000]);
    let mut request = [0u8; 16];
    request[0..4].copy_from_slice(&16u32.to_le_bytes());
    request[4..6].copy_from_slice(&18u16.to_le_bytes()); // RTM_GETLINK
    request[6..8].copy_from_slice(&0x301u16.to_le_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1u32.to_le_bytes());
    memory.write_bytes(0x1000, &request).expect("write request");
    assert_eq!(
        dispatcher
            .dispatch(
                context,
                SyscallRequest::new(206, SyscallArgs::from([fd as u64, 0x1000, 16, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .expect("send rtnetlink request"),
        DispatchOutcome::Returned { value: 16 },
    );
    let DispatchOutcome::Returned { value } = dispatcher
        .dispatch(
            context,
            SyscallRequest::new(207, SyscallArgs::from([fd as u64, 0x2000, 0x3000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .expect("receive rtnetlink reply")
    else {
        panic!("rtnetlink reply must be immediately readable");
    };
    memory
        .read_bytes(0x2000, usize::try_from(value).expect("reply length"))
        .expect("read rtnetlink reply")
}

fn ioctl_link_flags_and_mtu(
    dispatcher: &mut SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    name: &str,
) -> (u16, i32) {
    let fd = dispatch_socket(dispatcher, context, LINUX_AF_INET, LINUX_SOCK_DGRAM);
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x2000]);
    let mut ifreq = [0u8; 40];
    ifreq[..name.len()].copy_from_slice(name.as_bytes());

    memory.write_bytes(0x1000, &ifreq).expect("write ifreq");
    assert_eq!(
        dispatcher
            .dispatch(
                context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd as u64, LINUX_SIOCGIFFLAGS, 0x1000, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("dispatch SIOCGIFFLAGS"),
        DispatchOutcome::Returned { value: 0 },
    );
    let flag_bytes = memory.read_bytes(0x1010, 2).expect("read flags");
    let flags = u16::from_le_bytes([flag_bytes[0], flag_bytes[1]]);

    memory.write_bytes(0x1000, &ifreq).expect("reset ifreq");
    assert_eq!(
        dispatcher
            .dispatch(
                context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd as u64, LINUX_SIOCGIFMTU, 0x1000, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("dispatch SIOCGIFMTU"),
        DispatchOutcome::Returned { value: 0 },
    );
    let mtu_bytes = memory.read_bytes(0x1010, 4).expect("read MTU");
    let mtu = i32::from_le_bytes([mtu_bytes[0], mtu_bytes[1], mtu_bytes[2], mtu_bytes[3]]);
    (flags, mtu)
}

#[test]
fn two_live_containers_project_mutated_uts_and_netns_through_guest_surfaces() {
    let (_kernel, alpha, beta) = two_roots_for_guest_network_surfaces();
    let alpha_flags = carrick_abi::LINUX_IFF_UP
        | carrick_abi::LINUX_IFF_POINTOPOINT
        | carrick_abi::LINUX_IFF_NOARP;
    let beta_flags = carrick_abi::LINUX_IFF_UP
        | carrick_abi::LINUX_IFF_BROADCAST
        | carrick_abi::LINUX_IFF_PROMISC;
    let alpha_model = network_surface_model(
        "alpha0",
        std::net::Ipv4Addr::new(10, 81, 0, 2),
        alpha_flags,
        1401,
    );
    let beta_model = network_surface_model(
        "beta0",
        std::net::Ipv4Addr::new(10, 82, 0, 2),
        beta_flags,
        9001,
    );

    // Mutate after both roots exist: this catches a shared initial namespace,
    // stale launch snapshot, or dispatcher-global projection.
    alpha.task().uts_ns().set_nodename("alpha-mutated");
    beta.task().uts_ns().set_nodename("beta-mutated");
    alpha.task().net_ns().publish(alpha_model.clone());
    beta.task().net_ns().publish(beta_model.clone());

    let mut alpha_dispatcher = SyscallDispatcher::new();
    alpha_dispatcher.set_container(alpha.container());
    let mut beta_dispatcher = SyscallDispatcher::new();
    beta_dispatcher.set_container(beta.container());

    assert_eq!(
        dispatch_uname_nodename(&mut alpha_dispatcher, &alpha),
        "alpha-mutated"
    );
    assert_eq!(
        dispatch_uname_nodename(&mut beta_dispatcher, &beta),
        "beta-mutated"
    );

    assert_eq!(
        sysfs_link_view(&alpha),
        (vec!["lo".into(), "alpha0".into()], "1401\n".into())
    );
    assert_eq!(
        sysfs_link_view(&beta),
        (vec!["lo".into(), "beta0".into()], "9001\n".into())
    );

    let alpha_proc = proc_net_dev(&alpha);
    let beta_proc = proc_net_dev(&beta);
    assert!(alpha_proc.contains("alpha0:") && !alpha_proc.contains("beta0:"));
    assert!(beta_proc.contains("beta0:") && !beta_proc.contains("alpha0:"));

    let alpha_netlink = rtnetlink_link_dump(&mut alpha_dispatcher, &alpha);
    let beta_netlink = rtnetlink_link_dump(&mut beta_dispatcher, &beta);
    assert!(alpha_netlink.windows(7).any(|bytes| bytes == b"alpha0\0"));
    assert!(!alpha_netlink.windows(6).any(|bytes| bytes == b"beta0\0"));
    assert!(beta_netlink.windows(6).any(|bytes| bytes == b"beta0\0"));
    assert!(!beta_netlink.windows(7).any(|bytes| bytes == b"alpha0\0"));

    assert_eq!(
        ioctl_link_flags_and_mtu(&mut alpha_dispatcher, &alpha, "alpha0"),
        (alpha_flags as u16, 1401),
    );
    assert_eq!(
        ioctl_link_flags_and_mtu(&mut beta_dispatcher, &beta, "beta0"),
        (beta_flags as u16, 9001),
    );
}

fn test_directory_open_file(path: &str) -> OpenFile {
    let metadata = RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: RootFsEntryKind::Directory,
        mode: 0o755,
        size: 0,
    };
    OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::Directory {
            path: path.to_owned(),
            metadata,
            listing: DirListing::Pending,
            offset: 0,
            base: OpenDescriptionBase::new(0),
            trusted_host_dir: None,
        })),
        LINUX_O_RDONLY,
        0,
    )
}

#[test]
fn chroot_rebases_absolute_resolution() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/jail").unwrap();
    backend
        .set_file_contents("/jail/chroot02_testfile", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    dispatcher
        .capture_one_task_context()
        .unwrap()
        .resources()
        .fs_context()
        .set_chroot_root(Some("/jail".to_owned()));

    assert_eq!(
        dispatcher
            .resolve_at_path(LINUX_AT_FDCWD, "/chroot02_testfile")
            .unwrap(),
        "/jail/chroot02_testfile"
    );
    assert!(
        dispatcher
            .layered_metadata("/jail/chroot02_testfile")
            .is_ok()
    );
}

#[test]
fn chroot_no_search_permission_precedes_capability_error() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/jail").unwrap();
    backend.set_mode("/jail", 0o600).unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    dispatcher.set_credentials(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/jail\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(51, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(LINUX_EACCES)
    );
}

#[test]
fn truncate_follows_final_symlink_cycle_to_eloop() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.symlink("testsymlink2", "/testsymlink1").unwrap();
    backend.symlink("testsymlink1", "/testsymlink2").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/testsymlink1\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(45, SyscallArgs::from([0x4000, 256, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP)
    );
}

// === Trusted-dirfd fast lane (`--fs host`) ===

/// Host-backend dispatcher over a fixture walk tree:
/// `/walk/{file.txt, sub/deep.txt, link -> file.txt, fifo,
/// .carrick-lnkown.ghost}`. The sidecar name must stay invisible to the
/// guest; the FIFO exercises the never-blocking-open invariant.
#[cfg(target_os = "macos")]
fn trusted_lane_fixture() -> (tempfile::TempDir, SyscallDispatcher) {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/walk").unwrap();
    backend.make_dir("/walk/sub").unwrap();
    backend
        .set_file_contents("/walk/file.txt", b"hello lane".to_vec())
        .unwrap();
    backend
        .set_file_contents("/walk/sub/deep.txt", b"deep".to_vec())
        .unwrap();
    backend.symlink("file.txt", "/walk/link").unwrap();
    backend.create_fifo("/walk/fifo", 0o644).unwrap();
    backend
        .set_file_contents("/walk/.carrick-lnkown.ghost", b"sidecar".to_vec())
        .unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    (scratch, dispatcher)
}

/// LTP mknod04 semantics: a non-directory created in a setgid parent inherits
/// that parent's gid, but must not acquire S_ISGID unless the caller requested
/// it. Use Carrick's socket-node marker so the mode is deterministic even when
/// macOS refuses an unprivileged S_ISGID chmod on a real FIFO.
#[cfg(target_os = "macos")]
#[test]
fn mknodat_special_node_in_setgid_parent_inherits_gid_without_setgid() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/setgid-parent").unwrap();
    backend
        .set_owner(
            "/setgid-parent",
            Some(carrick_abi::NsUid::new(1234)),
            Some(carrick_abi::NsGid::new(11)),
        )
        .unwrap();
    // Force the guest-visible mode through the backend's metadata xattr: macOS
    // may clear a native directory S_ISGID bit when its real host gid differs.
    // The creator is not the guest owner and retains traversal via other+rwx.
    backend.set_mode("/setgid-parent", 0o2677).unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    dispatcher.set_credentials(
        carrick_abi::NsUid::new(65534),
        carrick_abi::NsGid::new(65534),
    );
    let parent = dispatcher
        .layered_metadata("/setgid-parent")
        .expect("setgid parent metadata");
    assert_ne!(parent.mode & 0o2000, 0, "fixture parent must be setgid");
    assert_eq!(
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .get_owner("/setgid-parent")
            .map(|(_, gid)| gid),
        Some(carrick_abi::NsGid::new(11)),
        "fixture parent must carry gid 11"
    );
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory
        .write_bytes(0x4000, b"/setgid-parent/socket-node\0")
        .unwrap();

    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            33,
            [
                LINUX_AT_FDCWD,
                0x4000,
                (LINUX_S_IFSOCK | 0o400) as u64,
                0,
                0,
                0,
            ],
        ),
        0,
        "mknodat socket node"
    );

    let stat = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/setgid-parent/socket-node",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(stat.gid, carrick_abi::NsGid::new(11), "inherit parent gid");
    assert_eq!(stat.mode & 0o2000, 0, "do not add unrequested S_ISGID");
}

/// CPython pathlib strict resolution: both stat ABIs must propagate ELOOP for
/// a final-component symlink cycle instead of misclassifying it as dangling.
#[cfg(target_os = "macos")]
#[test]
fn stat_following_final_symlink_cycle_returns_eloop() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.symlink("loop/inside", "/loop").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/loop\0").unwrap();
    let expected = -i64::from(crate::linux_abi::LINUX_ELOOP.get());

    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            79,
            [LINUX_AT_FDCWD, 0x4000, 0x4100, 0, 0, 0],
        ),
        expected,
        "newfstatat must preserve final-cycle ELOOP"
    );
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            291,
            [
                LINUX_AT_FDCWD,
                0x4000,
                0,
                LINUX_STATX_BASIC_STATS as u64,
                0x4200,
                0,
            ],
        ),
        expected,
        "statx must preserve final-cycle ELOOP"
    );
}

/// Cached-lower form of the walk fixture: the immutable image tree is a
/// real host directory and the writable host overlay starts sparse.
#[cfg(target_os = "macos")]
fn trusted_lower_lane_fixture() -> (tempfile::TempDir, tempfile::TempDir, SyscallDispatcher) {
    let lower = tempfile::tempdir().unwrap();
    let upper = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(lower.path().join("walk/sub")).unwrap();
    std::fs::write(lower.path().join("walk/file.txt"), b"lower file").unwrap();
    std::fs::write(lower.path().join("walk/sub/deep.txt"), b"deep").unwrap();
    std::os::unix::fs::symlink("file.txt", lower.path().join("walk/link")).unwrap();
    let lower_metadata = crate::fs_backend::HostFsBackend::attach(lower.path()).unwrap();
    lower_metadata.set_mode("/walk/file.txt", 0o4711).unwrap();
    lower_metadata
        .set_owner(
            "/walk/file.txt",
            Some(carrick_abi::NsUid::new(7)),
            Some(carrick_abi::NsGid::new(9)),
        )
        .unwrap();
    drop(lower_metadata);

    let rootfs = RootFs::from_immutable_host_dir(lower.path()).unwrap();
    let mut overlay = crate::fs_backend::HostFsBackend::from_path(upper.path()).unwrap();
    overlay.enable_sparse_upper_fast_miss();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(overlay));
    dispatcher.set_rootfs_layer(rootfs);
    (lower, upper, dispatcher)
}

#[cfg(target_os = "macos")]
fn lane_syscall(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    nr: u64,
    args: [u64; 6],
) -> i64 {
    let reporter = CompatReporter::default();
    match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value,
        DispatchOutcome::Errno { errno } => -i64::from(errno.get()),
        other => panic!("unexpected dispatch outcome: {other:?}"),
    }
}

#[cfg(target_os = "macos")]
fn lane_openat(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    dirfd: u64,
    path: &str,
    flags: u64,
) -> i64 {
    memory
        .write_bytes(0x4000, format!("{path}\0").as_bytes())
        .unwrap();
    lane_syscall(dispatcher, memory, 56, [dirfd, 0x4000, flags, 0, 0, 0])
}

#[cfg(target_os = "macos")]
fn lane_dir_is_trusted(dispatcher: &SyscallDispatcher, fd: i64) -> bool {
    let open_file = dispatcher.open_file(fd as i32).unwrap();
    matches!(
        open_file.description.read().as_deref(),
        Some(OpenDescription::Directory {
            trusted_host_dir: Some(_),
            ..
        })
    )
}

/// Drain getdents64 through the dispatcher and parse the guest-visible
/// `(name, d_type)` records (dot entries included).
#[cfg(target_os = "macos")]
fn lane_getdents(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    fd: i64,
) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    loop {
        let n = lane_syscall(dispatcher, memory, 61, [fd as u64, 0x8000, 4096, 0, 0, 0]);
        assert!(n >= 0, "getdents64 failed: {n}");
        if n == 0 {
            break;
        }
        let buf = memory.read_bytes(0x8000, n as usize).unwrap();
        let mut pos = 0usize;
        while pos < buf.len() {
            let reclen = u16::from_le_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            let d_type = buf[pos + 18];
            let name_bytes = &buf[pos + LINUX_DIRENT64_HEADER_SIZE..pos + reclen];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap();
            out.push((
                String::from_utf8(name_bytes[..end].to_vec()).unwrap(),
                d_type,
            ));
            pos += reclen;
        }
    }
    out
}

/// `lane_getdents`'s identity twin: the guest-visible `(name, d_ino)` records.
#[cfg(target_os = "macos")]
fn lane_getdents_inos(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    fd: i64,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    loop {
        let n = lane_syscall(dispatcher, memory, 61, [fd as u64, 0x8000, 4096, 0, 0, 0]);
        assert!(n >= 0, "getdents64 failed: {n}");
        if n == 0 {
            break;
        }
        let buf = memory.read_bytes(0x8000, n as usize).unwrap();
        let mut pos = 0usize;
        while pos < buf.len() {
            let d_ino = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
            let reclen = u16::from_le_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            let name_bytes = &buf[pos + LINUX_DIRENT64_HEADER_SIZE..pos + reclen];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap();
            out.push((
                String::from_utf8(name_bytes[..end].to_vec()).unwrap(),
                d_ino,
            ));
            pos += reclen;
        }
    }
    out
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_lane_serves_walk_and_recurses() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0, "open /walk: {root}");
    assert!(
        lane_dir_is_trusted(&dispatcher, root),
        "absolute O_DIRECTORY open must seed the trusted lane"
    );

    let sub = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "sub",
        LINUX_O_DIRECTORY,
    );
    assert!(sub >= 0, "openat(root, sub): {sub}");
    assert!(
        lane_dir_is_trusted(&dispatcher, sub),
        "a lane-served child directory must itself be trusted (walk recursion)"
    );

    let file = lane_openat(&mut dispatcher, &mut memory, sub as u64, "deep.txt", 0);
    assert!(file >= 0, "openat(sub, deep.txt): {file}");
    {
        let open_file = dispatcher.open_file(file as i32).unwrap();
        let open = open_file.description.read().expect("open description");
        assert!(
            matches!(&*open, OpenDescription::HostFile { .. }),
            "lane-served regular file must be a HostFile, got {open:?}"
        );
    }
    // The served fd carries the real bytes.
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 4);
    assert_eq!(memory.read_bytes(0x9000, 4).unwrap(), b"deep");

    // A missing single component is authoritative ENOENT from the lane.
    assert_eq!(
        lane_openat(&mut dispatcher, &mut memory, root as u64, "nope", 0),
        -i64::from(LINUX_ENOENT.get())
    );
    // O_DIRECTORY of a regular child is authoritative ENOTDIR.
    assert_eq!(
        lane_openat(
            &mut dispatcher,
            &mut memory,
            root as u64,
            "file.txt",
            LINUX_O_DIRECTORY
        ),
        -i64::from(LINUX_ENOTDIR.get())
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_immutable_lower_serves_walk_recursively_while_upper_is_unchanged() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0, "open lower /walk: {root}");
    assert!(
        lane_dir_is_trusted(&dispatcher, root),
        "an upper-absent immutable-lower directory must seed the trusted lane"
    );

    let sub = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "sub",
        LINUX_O_DIRECTORY,
    );
    assert!(sub >= 0, "open lower sub: {sub}");
    assert!(
        lane_dir_is_trusted(&dispatcher, sub),
        "unchanged sparse-upper state must propagate lower trust"
    );

    let file = lane_openat(&mut dispatcher, &mut memory, sub as u64, "deep.txt", 0);
    assert!(file >= 0, "open lower deep.txt: {file}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 4);
    assert_eq!(memory.read_bytes(0x9000, 4).unwrap(), b"deep");
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_immutable_lower_falls_back_after_an_upper_shadow() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0 && lane_dir_is_trusted(&dispatcher, root));

    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/file.txt", b"upper file".to_vec())
        .unwrap();

    let file = lane_openat(&mut dispatcher, &mut memory, root as u64, "file.txt", 0);
    assert!(file >= 0, "open upper shadow through lower dirfd: {file}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 10);
    assert_eq!(
        memory.read_bytes(0x9000, 10).unwrap(),
        b"upper file",
        "a stale lower anchor must not bypass the writable shadow"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_immutable_lower_stat_preserves_layered_guest_identity() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(root >= 0 && lane_dir_is_trusted(&dispatcher, root));

    let fast = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "file.txt",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    let slow = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/file.txt",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(fast, slow, "trusted lower stat must equal layered stat");
    assert_eq!(fast.mode & 0o7777, 0o4711);
}

/// LTP `creat05` shape: the test `mkdir`s its own scratch directory (which
/// only the WRITABLE upper holds — the immutable lower never had it), fills
/// it with thousands of files, and then `open(O_DIRECTORY)`s it through the
/// harness. An upper-only directory under an immutable lower must seed the
/// trusted lane exactly like a lower-only one: the lower's absence is
/// permanent, so the upper dirfd IS the merged namespace for that subtree.
/// Before this landed the open fell to the layered path and enumerated
/// every child (fstatat + open + flistxattr + close each) on EVERY open.
#[cfg(target_os = "macos")]
#[test]
fn trusted_upper_only_directory_seeds_the_lane_and_streams() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    memory.write_bytes(0x4200, b"/walk/scratch\0").unwrap();
    let mk = lane_syscall(
        &mut dispatcher,
        &mut memory,
        34,
        [LINUX_AT_FDCWD, 0x4200, 0o755, 0, 0, 0],
    );
    assert_eq!(mk, 0, "mkdirat /walk/scratch: {mk}");
    for name in ["a.txt", "b.txt"] {
        let fd = lane_openat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            &format!("/walk/scratch/{name}"),
            LINUX_O_CREAT | LINUX_O_WRONLY,
        );
        assert!(fd >= 0, "create {name}: {fd}");
        memory.write_bytes(0x9000, name.as_bytes()).unwrap();
        let n = lane_syscall(
            &mut dispatcher,
            &mut memory,
            64,
            [fd as u64, 0x9000, name.len() as u64, 0, 0, 0],
        );
        assert_eq!(n, name.len() as i64);
        assert_eq!(
            lane_syscall(&mut dispatcher, &mut memory, 57, [fd as u64, 0, 0, 0, 0, 0]),
            0
        );
    }

    let dir = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk/scratch",
        LINUX_O_DIRECTORY,
    );
    assert!(dir >= 0, "open upper-only /walk/scratch: {dir}");
    assert!(
        lane_dir_is_trusted(&dispatcher, dir),
        "an upper-only directory whose lower is permanently absent must seed the trusted lane"
    );

    // Children resolve through the upper dirfd.
    let file = lane_openat(&mut dispatcher, &mut memory, dir as u64, "a.txt", 0);
    assert!(file >= 0, "open a.txt through the upper dirfd: {file}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [file as u64, 0x9100, 64, 0, 0, 0],
    );
    assert_eq!(n, 5);
    assert_eq!(memory.read_bytes(0x9100, 5).unwrap(), b"a.txt");
    let missing = lane_openat(&mut dispatcher, &mut memory, dir as u64, "nope", 0);
    assert_eq!(missing, -i64::from(LINUX_ENOENT.get()));

    // The listing equals the layered truth.
    let mut streamed = lane_getdents(&mut dispatcher, &mut memory, dir);
    streamed.retain(|(n, _)| n != "." && n != "..");
    streamed.sort();
    let mut layered: Vec<(String, u8)> = crate::overlay::layered_directory_entries(
        dispatcher.fs.rootfs_vfs.overlay.as_ref(),
        dispatcher.fs.rootfs_vfs.rootfs.as_ref(),
        "/walk/scratch",
    )
    .unwrap()
    .into_iter()
    .map(|e| (e.name, linux_dirent_type(e.metadata.kind)))
    .collect();
    layered.sort();
    assert_eq!(streamed, layered);
    assert_eq!(streamed.len(), 2);

    // A MERGED directory (lower + upper contributions) still takes the
    // exact layered path: /walk itself now has an upper child.
    let merged = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(merged >= 0);
    let mut listed = lane_getdents(&mut dispatcher, &mut memory, merged);
    listed.retain(|(n, _)| n != "." && n != "..");
    let names: Vec<&str> = listed.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"scratch"), "{names:?}");
    assert!(names.contains(&"file.txt"), "{names:?}");
    assert!(names.contains(&"sub"), "{names:?}");
}

/// A directory listing is taken when the guest READS it, not when it opens
/// it (Linux `getdents64` walks the live dentry tree; `rewinddir` re-reads).
/// Two consequences the old open-time snapshot got wrong — and one cost:
/// every `open(O_DIRECTORY)` walk anchor paid a full enumeration (O(n)
/// stats) whether or not the guest ever listed it, which is what put
/// `creat05` at 8x the oracle.
#[cfg(target_os = "macos")]
#[test]
fn directory_listing_is_taken_at_read_time_not_open_time() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    // Shadow a lower file so /walk is a MERGED directory that cannot take
    // the trusted lane.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/file.txt", b"upper".to_vec())
        .unwrap();
    let dir = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(dir >= 0);
    assert!(!lane_dir_is_trusted(&dispatcher, dir));
    {
        let open_file = dispatcher.open_file(dir as i32).unwrap();
        let open = open_file.description.read().unwrap();
        let OpenDescription::Directory { listing, .. } = &*open else {
            panic!("expected a directory description");
        };
        assert!(
            matches!(listing, DirListing::Pending),
            "open(O_DIRECTORY) must not enumerate the directory: {listing:?}"
        );
    }

    // Created AFTER the open, BEFORE the first read: visible (Linux).
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/after-open.txt", b"x".to_vec())
        .unwrap();
    let first = lane_getdents(&mut dispatcher, &mut memory, dir);
    assert!(
        first.iter().any(|(n, _)| n == "after-open.txt"),
        "a child created before the first getdents must be listed: {first:?}"
    );
    assert!(first.iter().any(|(n, _)| n == "file.txt"));

    // Created after the first drain: visible after a rewind (rewinddir).
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/after-drain.txt", b"y".to_vec())
        .unwrap();
    let again = lane_getdents(&mut dispatcher, &mut memory, dir);
    assert!(again.is_empty(), "a drained directory reads EOF: {again:?}");
    let seek = lane_syscall(
        &mut dispatcher,
        &mut memory,
        62,
        [dir as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(seek, 0);
    let rewound = lane_getdents(&mut dispatcher, &mut memory, dir);
    assert!(
        rewound.iter().any(|(n, _)| n == "after-drain.txt"),
        "a rewound untrusted directory must re-read: {rewound:?}"
    );
}

/// The three lanes that publish a file's identity — `stat(path)`,
/// `fstat(open(path))` and `getdents64`'s `d_ino` — must agree for an entry
/// only the immutable cache lower holds.
///
/// The fd lane opens the lower's REAL host file and reports its APFS inode,
/// and `getdents64` already publishes that same inode, but the path lane
/// dropped it at the `RootFsMetadata` boundary and hashed the path instead.
/// GNU coreutils `cp` stats its source through the path AND the fd it opened,
/// and refuses the copy when the two disagree — `cp: skipping file '…', as it
/// was replaced while being copied` — which broke LTP `execve02`'s setup with
/// TBROK the moment the cached lower was enabled for HvPatch.
#[cfg(target_os = "macos")]
#[test]
fn immutable_lower_reports_one_inode_through_stat_fstat_and_getdents() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    for (dir, name) in [("/walk", "file.txt"), ("/walk/sub", "deep.txt")] {
        let full = format!("{dir}/{name}");
        let by_path = dispatcher
            .path_stat_record(
                &dispatcher.exact_signal_context_for_test(),
                LINUX_AT_FDCWD,
                &full,
                LINUX_AT_SYMLINK_NOFOLLOW,
            )
            .unwrap();

        let fd = lane_openat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, &full, 0);
        assert!(fd >= 0, "open lower-only {full}: {fd}");
        let by_fd = dispatcher.fd_stat_record(fd as i32).unwrap();
        assert_eq!(
            by_path.ino, by_fd.ino,
            "stat({full}).st_ino must equal fstat(open({full})).st_ino"
        );

        let dirfd = lane_openat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            dir,
            LINUX_O_DIRECTORY,
        );
        assert!(dirfd >= 0, "open lower-only dir {dir}: {dirfd}");
        let d_ino = lane_getdents_inos(&mut dispatcher, &mut memory, dirfd)
            .into_iter()
            .find(|(entry, _)| entry == name)
            .unwrap_or_else(|| panic!("{name} missing from getdents64 of {dir}"))
            .1;
        assert_eq!(
            d_ino, by_path.ino,
            "getdents64 d_ino for {full} must equal its stat st_ino"
        );
    }
}

/// A lower-only DIRECTORY must satisfy the same identity invariant: Python's
/// `shutil.rmtree` and Go's `os.SameFile` compare `lstat(dir)` against
/// `fstat(open(dir))` and refuse to recurse when they differ.
#[cfg(target_os = "macos")]
#[test]
fn immutable_lower_directory_path_stat_matches_its_fd_stat() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    let by_path = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/sub",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    let dirfd = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk/sub",
        LINUX_O_DIRECTORY,
    );
    assert!(dirfd >= 0, "open lower-only directory: {dirfd}");
    let by_fd = dispatcher.fd_stat_record(dirfd as i32).unwrap();
    assert_eq!(
        by_path.ino, by_fd.ino,
        "lstat(dir).st_ino must equal fstat(open(dir)).st_ino"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn fstat_caches_host_xattrs_and_invalidates_on_mutators() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let fd = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk/file.txt",
        0,
    );
    assert!(fd >= 0);

    // Initial fstat
    crate::fs_backend::reset_host_xattr_read_count();
    let st1 = dispatcher.fd_stat_record(fd as i32).unwrap();
    assert_eq!(st1.mode & 0o7777, 0o4711);
    assert_eq!(st1.uid.raw(), 7);
    assert_eq!(st1.gid.raw(), 9);

    // Repeat fstat: MUST be 0 host xattr reads!
    let reads_before = crate::fs_backend::host_xattr_read_count();
    let st2 = dispatcher.fd_stat_record(fd as i32).unwrap();
    let reads_after = crate::fs_backend::host_xattr_read_count();
    assert_eq!(
        reads_after, reads_before,
        "repeat fstat must perform 0 host xattr reads"
    );
    assert_eq!(st1, st2);

    // Mutator: fchmod
    const SYS_FCHMOD: u64 = 52;
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        SYS_FCHMOD,
        [fd as u64, 0o644, 0, 0, 0, 0],
    );
    assert_eq!(rc, 0);

    // fstat after mutator: must reflect updated mode AND force a refresh
    crate::fs_backend::reset_host_xattr_read_count();
    let st3 = dispatcher.fd_stat_record(fd as i32).unwrap();
    assert_eq!(st3.mode & 0o7777, 0o644);
    assert!(
        crate::fs_backend::host_xattr_read_count() > 0,
        "fstat after mutator must refresh"
    );

    // Repeat fstat again: MUST be 0 host xattr reads!
    let reads_before = crate::fs_backend::host_xattr_read_count();
    let st4 = dispatcher.fd_stat_record(fd as i32).unwrap();
    let reads_after = crate::fs_backend::host_xattr_read_count();
    assert_eq!(
        reads_after, reads_before,
        "repeat fstat must perform 0 host xattr reads"
    );
    assert_eq!(st3, st4);

    // Mutator: fchown
    const SYS_FCHOWN: u64 = 55;
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        SYS_FCHOWN,
        [fd as u64, 42, 84, 0, 0, 0],
    );
    assert_eq!(rc, 0);

    // fstat after fchown: must reflect updated owner AND force a refresh
    crate::fs_backend::reset_host_xattr_read_count();
    let st5 = dispatcher.fd_stat_record(fd as i32).unwrap();
    assert_eq!(st5.uid.raw(), 42);
    assert_eq!(st5.gid.raw(), 84);
    assert!(
        crate::fs_backend::host_xattr_read_count() > 0,
        "fstat after fchown must refresh"
    );

    // Repeat fstat again: MUST be 0 host xattr reads!
    let reads_before = crate::fs_backend::host_xattr_read_count();
    let st6 = dispatcher.fd_stat_record(fd as i32).unwrap();
    let reads_after = crate::fs_backend::host_xattr_read_count();
    assert_eq!(
        reads_after, reads_before,
        "repeat fstat must perform 0 host xattr reads"
    );
    assert_eq!(st5, st6);
}

#[cfg(target_os = "macos")]
#[test]
fn deep_tree_lookups_and_negative_opens_via_dentry_cache() {
    let (lower, upper, mut dispatcher) = trusted_lower_lane_fixture();
    let deep_dir = lower.path().join("d1/d2/d3/d4/d5/d6");
    std::fs::create_dir_all(&deep_dir).unwrap();
    std::fs::write(deep_dir.join("leaf.txt"), b"leaf content").unwrap();

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // 1. Initial stat and open to warm the dentry cache
    let path = "/d1/d2/d3/d4/d5/d6/leaf.txt";
    let st = dispatcher.fs.rootfs_vfs.dentry_stat(path, false).unwrap();
    assert_eq!(st.size, 12);

    let fd = lane_openat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, path, 0);
    assert!(fd >= 0);

    // 2. Warm cache stat: MUST be <= 1 host syscall (0 openat per component)
    dispatcher
        .fs
        .rootfs_vfs
        .dentry_cache
        .reset_host_open_count();
    let st2 = dispatcher.fs.rootfs_vfs.dentry_stat(path, false).unwrap();
    assert_eq!(st2.size, 12);
    assert_eq!(
        dispatcher.fs.rootfs_vfs.dentry_cache.host_open_count(),
        0,
        "warm stat must take 0 host opens"
    );

    // 3. Warm cache open: MUST take exactly 1 host openat (at the leaf, 0 per component)
    dispatcher
        .fs
        .rootfs_vfs
        .dentry_cache
        .reset_host_open_count();
    let fd2 = lane_openat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, path, 0);
    assert!(fd2 >= 0);
    assert_eq!(
        dispatcher.fs.rootfs_vfs.dentry_cache.host_open_count(),
        1,
        "warm open of existing file must take exactly 1 host openat (the leaf)"
    );

    // 4. Relative open on warm cache: MUST take exactly 1 host openat (the leaf)
    dispatcher
        .fs
        .rootfs_vfs
        .dentry_cache
        .reset_host_open_count();
    let rel_path = "d1/d2/d3/d4/d5/d6/leaf.txt";
    let fd3 = lane_openat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, rel_path, 0);
    assert!(fd3 >= 0);
    assert_eq!(
        dispatcher.fs.rootfs_vfs.dentry_cache.host_open_count(),
        1,
        "relative open on warm cache must take exactly 1 host openat (the leaf)"
    );

    // 5. Negative lookup: open non-existent file under 6-deep dir
    let missing_path = "/d1/d2/d3/d4/d5/d6/missing.txt";
    let missing_fd = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        missing_path,
        0,
    );
    assert_eq!(missing_fd, -(crate::linux_abi::LINUX_ENOENT.get() as i64));

    // Repeat negative open: MUST be cached and take 0 host opens
    dispatcher
        .fs
        .rootfs_vfs
        .dentry_cache
        .reset_host_open_count();
    let missing_fd2 = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        missing_path,
        0,
    );
    assert_eq!(missing_fd2, -(crate::linux_abi::LINUX_ENOENT.get() as i64));
    assert_eq!(
        dispatcher.fs.rootfs_vfs.dentry_cache.host_open_count(),
        0,
        "cached negative open must take 0 host opens"
    );

    // 6. Invalidation by create: create the missing file in upper
    let upper_deep = upper.path().join("d1/d2/d3/d4/d5/d6");
    std::fs::create_dir_all(&upper_deep).unwrap();
    std::fs::write(upper_deep.join("missing.txt"), b"now created").unwrap();
    // Notify VFS mutator of creation (as open(O_CREAT) or mknod does)
    dispatcher
        .fs
        .rootfs_vfs
        .dentry_cache
        .entry_created(missing_path, None);

    // Opening newly created file must now succeed!
    let created_fd = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        missing_path,
        0,
    );
    assert!(created_fd >= 0, "open after create must succeed");
}

/// A lower-only file's `st_mtime`/`st_nlink` must come from the real host
/// inode too. The path lane reported `mtime=0`/`nlink=1` for every untouched
/// image file, so `make`-style newer-than comparisons saw the epoch.
#[cfg(target_os = "macos")]
#[test]
fn immutable_lower_path_stat_reports_real_mtime_and_nlink() {
    let (lower, _upper, dispatcher) = trusted_lower_lane_fixture();
    let host = std::fs::metadata(lower.path().join("walk/sub/deep.txt")).unwrap();

    let record = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/sub/deep.txt",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();

    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        record.mtime.0,
        host.mtime(),
        "an untouched lower file must not report the epoch as its mtime"
    );
    assert_eq!(record.nlink, host.nlink() as u32);
}

#[cfg(target_os = "macos")]
#[test]
fn absolute_readonly_open_can_install_an_upper_absent_lower_file_directly() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let outcome = dispatcher
        .try_immutable_lower_absolute_open(LINUX_AT_FDCWD, "/walk/file.txt", LINUX_O_RDONLY)
        .expect("eligible absolute lower open should take the direct lane");
    let DispatchOutcome::Returned { value: fd } = outcome else {
        panic!("unexpected direct-open outcome: {outcome:?}");
    };

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [fd as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 10);
    assert_eq!(memory.read_bytes(0x9000, 10).unwrap(), b"lower file");
}

#[cfg(target_os = "macos")]
#[test]
fn dentry_fast_open_preserves_nofollow_after_following_stat() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    // Warm the follow cache, then request the distinct no-follow contract.
    dispatcher.layered_metadata("/walk/link").unwrap();
    let result = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk/link",
        LINUX_O_RDONLY | LinuxOpenFlags::NOFOLLOW.bits(),
    );
    assert_eq!(result, -i64::from(crate::linux_abi::LINUX_ELOOP.get()));
}

#[cfg(target_os = "macos")]
#[test]
fn absolute_lower_fast_open_refuses_nofollow_symlink_semantics() {
    let (_lower, _upper, dispatcher) = trusted_lower_lane_fixture();
    assert!(
        dispatcher
            .try_immutable_lower_absolute_open(
                LINUX_AT_FDCWD,
                "/walk/link",
                LINUX_O_RDONLY | LinuxOpenFlags::NOFOLLOW.bits(),
            )
            .is_none(),
        "O_NOFOLLOW must reach the layered lstat path and return ELOOP"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_lane_falls_back_for_special_shapes() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));

    // Multi-component and ".." names take (and succeed via) the full path.
    let multi = lane_openat(&mut dispatcher, &mut memory, root as u64, "sub/deep.txt", 0);
    assert!(multi >= 0, "multi-component openat: {multi}");
    let up = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "..",
        LINUX_O_DIRECTORY,
    );
    assert!(up >= 0, "dotdot openat: {up}");

    // A symlink child falls back and is FOLLOWED (the lane would ELOOP).
    let via_link = lane_openat(&mut dispatcher, &mut memory, root as u64, "link", 0);
    assert!(via_link >= 0, "symlink-child openat: {via_link}");
    let n = lane_syscall(
        &mut dispatcher,
        &mut memory,
        63,
        [via_link as u64, 0x9000, 64, 0, 0, 0],
    );
    assert_eq!(n, 10);
    assert_eq!(memory.read_bytes(0x9000, 10).unwrap(), b"hello lane");

    // O_CREAT falls back and actually creates.
    let created = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "made.txt",
        LINUX_O_CREAT | LINUX_O_WRONLY,
    );
    assert!(created >= 0, "O_CREAT openat: {created}");
    assert!(dispatcher.layered_metadata("/walk/made.txt").is_ok());

    // A FIFO child must route to the non-blocking FIFO machinery — a
    // HostPipe, never a HostFile, and never a blocking open.
    let fifo = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "fifo",
        LINUX_O_RDWR,
    );
    assert!(fifo >= 0, "fifo openat: {fifo}");
    {
        let open_file = dispatcher.open_file(fifo as i32).unwrap();
        let open = open_file.description.read().expect("open description");
        assert!(
            matches!(&*open, OpenDescription::HostPipe { .. }),
            "FIFO child must be a HostPipe, got {open:?}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_stat_matches_slow_path() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    // A carrick mode xattr (setuid bits) + owner xattrs must merge into
    // the fast-lane record exactly as the slow path merges them.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_mode("/walk/file.txt", 0o4711)
        .unwrap();
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_owner(
            "/walk/file.txt",
            Some(carrick_abi::NsUid::new(7)),
            Some(carrick_abi::NsGid::new(9)),
        )
        .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));

    // A mknod device MARKER: the mode xattr carries the S_IFCHR type bits
    // verbatim and the rdev xattr the raw dev_t — the fast lane must
    // recover both through `stat_record_with_device` like the slow path.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .create_device("/walk/dev0", LINUX_S_IFCHR | 0o600, 0x0103)
        .unwrap();

    for name in ["file.txt", "sub", "link", "fifo", "dev0"] {
        let fast = dispatcher.path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            name,
            LINUX_AT_SYMLINK_NOFOLLOW,
        );
        let slow = dispatcher.path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            &format!("/walk/{name}"),
            LINUX_AT_SYMLINK_NOFOLLOW,
        );
        assert_eq!(fast, slow, "fast/slow stat divergence for {name:?}");
    }
    let dev = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "dev0",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(dev.mode & LINUX_S_IFMT, LINUX_S_IFCHR);
    assert_eq!(dev.rdev, 0x0103);
    // Missing child: authoritative ENOENT, identical to the slow path.
    assert_eq!(
        dispatcher.path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "gone",
            0
        ),
        Err(LINUX_ENOENT)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn trusted_getdents_streams_layered_identical_entries() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));
    // Streaming preconditions hold on this fixture (a real FIFO is not
    // interference; the sidecar is name-filtered by the stream itself).
    assert!(
        !dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .dir_has_overlay_interference("/walk")
    );

    let mut streamed = lane_getdents(&mut dispatcher, &mut memory, root);
    assert_eq!(streamed.first().map(|(n, _)| n.as_str()), Some("."));
    assert_eq!(streamed.get(1).map(|(n, _)| n.as_str()), Some(".."));
    streamed.retain(|(n, _)| n != "." && n != "..");
    streamed.sort();

    let mut layered: Vec<(String, u8)> = crate::overlay::layered_directory_entries(
        dispatcher.fs.rootfs_vfs.overlay.as_ref(),
        None,
        "/walk",
    )
    .unwrap()
    .into_iter()
    .map(|e| (e.name, linux_dirent_type(e.metadata.kind)))
    .collect();
    layered.sort();

    assert_eq!(streamed, layered);
    assert!(
        !streamed.iter().any(|(n, _)| n.starts_with(".carrick-")),
        "sidecar names must never reach the guest: {streamed:?}"
    );
    assert!(
        streamed
            .iter()
            .any(|(n, t)| n == "fifo" && *t == linux_dirent_type(RootFsEntryKind::Fifo)),
        "FIFO child must stream as DT_FIFO without being opened"
    );
    assert!(
        streamed
            .iter()
            .any(|(n, t)| n == "link" && *t == linux_dirent_type(RootFsEntryKind::Symlink))
    );
    assert!(
        streamed
            .iter()
            .any(|(n, t)| n == "sub" && *t == linux_dirent_type(RootFsEntryKind::Directory))
    );

    // Rewind refreshes: a child created AFTER the first drain appears on
    // the re-read (Linux rewinddir semantics).
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .set_file_contents("/walk/late.txt", b"x".to_vec())
        .unwrap();
    let seek = lane_syscall(
        &mut dispatcher,
        &mut memory,
        62,
        [root as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(seek, 0);
    let refreshed = lane_getdents(&mut dispatcher, &mut memory, root);
    assert!(
        refreshed.iter().any(|(n, _)| n == "late.txt"),
        "rewound trusted getdents must take a fresh snapshot: {refreshed:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn socket_marker_disables_streaming_and_keeps_layered_parity() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    // A bound AF_UNIX socket node is a MARKER regular file whose guest
    // TYPE lives in an xattr; its presence must disable streaming (fail
    // closed to the layered path) so getdents can never diverge from the
    // layered truth.
    dispatcher
        .fs
        .rootfs_vfs
        .overlay
        .create_socket("/walk/sock", 0o755)
        .unwrap();
    assert!(
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .dir_has_overlay_interference("/walk")
    );
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));
    // getdents through the trusted fd equals the layered merge exactly.
    // (Note the HOST layered path itself reports a socket MARKER as
    // DT_REG — child_names cannot classify markers without a per-child
    // open; stat is where S_IFSOCK is recovered. The lane preserves that
    // behavior bit-for-bit.)
    let mut entries = lane_getdents(&mut dispatcher, &mut memory, root);
    entries.retain(|(n, _)| n != "." && n != "..");
    entries.sort();
    let mut layered: Vec<(String, u8)> = crate::overlay::layered_directory_entries(
        dispatcher.fs.rootfs_vfs.overlay.as_ref(),
        None,
        "/walk",
    )
    .unwrap()
    .into_iter()
    .map(|e| (e.name, linux_dirent_type(e.metadata.kind)))
    .collect();
    layered.sort();
    assert_eq!(entries, layered);
    assert!(entries.iter().any(|(n, _)| n == "sock"));

    // The fast STAT lane recovers S_IFSOCK from the marker xattr exactly
    // like the slow path.
    let fast = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            root as u64,
            "sock",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(fast.mode & LINUX_S_IFMT, LINUX_S_IFSOCK);
    let slow = dispatcher
        .path_stat_record(
            &dispatcher.exact_signal_context_for_test(),
            LINUX_AT_FDCWD,
            "/walk/sock",
            LINUX_AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
    assert_eq!(fast, slow);
}

#[test]
fn fd_allocator_cursor_reuses_closed_hole_then_advances() {
    let mut dispatcher = SyscallDispatcher::new();
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let base_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/base"))
        .unwrap();
    assert_eq!(base_fd, 3);

    for expected in 4..36 {
        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(23, SyscallArgs::from([base_fd as u64, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: expected }
        );
    }

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(57, SyscallArgs::from([10, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(23, SyscallArgs::from([base_fd as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 10 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(23, SyscallArgs::from([base_fd as u64, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 36 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

fn sigpoll_fd(info: carrick_abi::LinuxSiginfo) -> i32 {
    i32::from_le_bytes(info._pad[0..4].try_into().unwrap())
}

fn take_process_sigpoll_fd(context: &crate::kernel::KernelContext, signum: i32) -> i32 {
    let pending = context
        .shared()
        .pending_signals()
        .take_lowest_in(carrick_abi::SigSet::EMPTY.with(signum))
        .expect("process-directed dnotify signal");
    sigpoll_fd(pending.siginfo.expect("dnotify siginfo"))
}

#[test]
fn dnotify_child_attrib_queues_parent_before_child() {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.exact_signal_context_for_test();
    let tid = context.thread().registry_id();
    let signum = 34;

    let parent_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/watched"))
        .unwrap();
    let child_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/watched/child"))
        .unwrap();
    dispatcher
        .open_file(parent_fd)
        .unwrap()
        .description
        .common()
        .set_async_sig(signum);
    dispatcher
        .open_file(child_fd)
        .unwrap()
        .description
        .common()
        .set_async_sig(signum);

    dispatcher
        .dnotify_register(
            &context,
            parent_fd,
            LinuxDnotifyMask::ATTRIB | LinuxDnotifyMask::MULTISHOT,
            tid,
        )
        .unwrap();
    dispatcher
        .dnotify_register(
            &context,
            child_fd,
            LinuxDnotifyMask::ATTRIB | LinuxDnotifyMask::MULTISHOT,
            tid,
        )
        .unwrap();

    dispatcher.dnotify_attrib(
        &dispatcher.exact_signal_context_for_test(),
        "/watched/child",
    );

    assert_eq!(take_process_sigpoll_fd(&context, signum), parent_fd);
    assert_eq!(take_process_sigpoll_fd(&context, signum), child_fd);
}

#[test]
fn dnotify_child_attrib_matches_macos_private_tmp_alias() {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.exact_signal_context_for_test();
    let tid = context.thread().registry_id();
    let signum = 34;

    let parent_fd = dispatcher
        .install_fd_at_or_above(3, test_directory_open_file("/private/tmp/watched"))
        .unwrap();
    dispatcher
        .open_file(parent_fd)
        .unwrap()
        .description
        .common()
        .set_async_sig(signum);

    dispatcher
        .dnotify_register(
            &context,
            parent_fd,
            LinuxDnotifyMask::ATTRIB | LinuxDnotifyMask::MULTISHOT,
            tid,
        )
        .unwrap();

    dispatcher.dnotify_attrib(
        &dispatcher.exact_signal_context_for_test(),
        "/tmp/watched/child",
    );

    assert_eq!(take_process_sigpoll_fd(&context, signum), parent_fd);
}

#[test]
fn staged_splice_pipe_bytes_preserve_fifo_order() {
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);

    let dispatcher = SyscallDispatcher::new();
    let read_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[0]),
            is_read_end: true,
            pipe_id: 42,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_RDONLY,
        0,
    );
    let write_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 42,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_WRONLY,
        0,
    );
    let (read_fd, _write_fd) = dispatcher
        .install_fd_pair_at_or_above(3, read_open, write_open)
        .expect("install host pipe pair");
    let host_read = dispatcher
        .host_pipe_read_fd(read_fd)
        .expect("host pipe read fd");

    dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"abc".to_vec());
    dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"def".to_vec());

    let bytes = dispatcher
        .take_splice_pipe_bytes(read_fd, host_read, None, 6, false)
        .expect("take staged bytes")
        .expect("staged bytes are available without waiting");
    assert_eq!(bytes, b"abcdef");
}

#[test]
fn staged_splice_pipe_bytes_are_visible_to_read() {
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
    for host_fd in host_fds {
        assert_ne!(
            unsafe { libc::fcntl(host_fd, libc::F_SETFL, libc::O_NONBLOCK) },
            -1
        );
    }

    let mut dispatcher = SyscallDispatcher::new();
    let read_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[0]),
            is_read_end: true,
            pipe_id: 43,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_RDONLY,
        0,
    );
    let write_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 43,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_WRONLY,
        0,
    );
    let (read_fd, _write_fd) = dispatcher
        .install_fd_pair_at_or_above(3, read_open, write_open)
        .expect("install host pipe pair");

    dispatcher.stage_splice_pipe_bytes_owned(read_fd, b"AAAABBBB".to_vec());
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
    let outcome = dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(63, SyscallArgs::from([read_fd as u64, 0x1000, 4, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .expect("read dispatch");

    assert_eq!(outcome, DispatchOutcome::Returned { value: 4 });
    assert_eq!(memory.read_bytes(0x1000, 4).unwrap(), b"AAAA");
    assert_eq!(dispatcher.staged_splice_pipe_bytes(read_fd), 4);
}

#[test]
fn staged_splice_bytes_on_shared_description_survives_draining_table() {
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
    for host_fd in host_fds {
        assert_ne!(
            unsafe { libc::fcntl(host_fd, libc::F_SETFL, libc::O_NONBLOCK) },
            -1
        );
    }

    let dispatcher = SyscallDispatcher::new();
    let read_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[0]),
            is_read_end: true,
            pipe_id: 44,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_RDONLY,
        0,
    );
    let write_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 44,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_WRONLY,
        0,
    );
    let (read_fd, _write_fd) = dispatcher
        .install_fd_pair_at_or_above(3, read_open, write_open)
        .expect("install host pipe pair");

    let desc = dispatcher.open_file(read_fd).unwrap().description;

    let ids = crate::kernel::ObjectIdRegistry::new();
    let child_table = Arc::new(crate::kernel::FileTable::new(
        ids.file_table_id().expect("child table id"),
    ));
    child_table.install(
        crate::kernel::FileSlotNumber::for_open_fd(3).expect("fd"),
        dispatcher.open_file(read_fd).unwrap().description,
        false,
    );

    child_table.drain_functional_refs();

    crate::dispatch::resources::with_dirty_retiring_resources_for_executor_test(
        Arc::clone(&child_table),
        || {
            dispatcher.stage_splice_bytes_for_description(&desc, b"rescued".to_vec());
        },
    );

    let host_read = dispatcher.host_pipe_read_fd(read_fd).expect("host read fd");
    let bytes = dispatcher
        .take_splice_pipe_bytes(read_fd, host_read, None, 7, false)
        .expect("take staged bytes")
        .expect("staged bytes available");
    assert_eq!(bytes, b"rescued");
}

/// `splice(2)` from a host-backed file into a pipe must BOTH advance the
/// source's kernel offset when `off_in` is NULL AND return a SHORT count
/// bounded by the destination pipe. `write(2)` may block until every byte
/// lands; `splice(2)` may not — and coreutils `cat` drains its bounce pipe
/// only AFTER the splice returns, so a "deliver it all" splice deadlocks a
/// single-threaded guest, while a non-advancing offset re-sends byte 0
/// forever. Both shapes hung `cat` on `ubuntu:latest` (uutils).
#[test]
fn splice_host_file_to_pipe_returns_short_and_advances_offset() {
    let mut path = std::env::temp_dir();
    path.push(format!("carrick-splice-loop-{}", std::process::id()));
    // Larger than any pipe buffer, so one splice CANNOT move it all.
    let contents = vec![0xa5u8; 512 * 1024];
    std::fs::write(&path, &contents).expect("write splice source");

    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let host_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    assert!(host_fd >= 0, "open splice source");

    let dispatcher = SyscallDispatcher::new();
    let source = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostFile {
            host_fd: HostFdRef::new(host_fd),
            metadata: RootFsMetadata {
                path: path.clone(),
                kind: RootFsEntryKind::File,
                mode: 0o644,
                size: contents.len(),
            },
            base: OpenDescriptionBase::new(0),
            writable: false,
        })),
        LINUX_O_RDONLY,
        0,
    );
    let in_fd = dispatcher
        .install_fd_at_or_above(3, source)
        .expect("install splice source fd");

    let mut host_pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_pipe.as_mut_ptr()) }, 0);
    let read_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_pipe[0]),
            is_read_end: true,
            pipe_id: 4242,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_RDONLY,
        0,
    );
    let write_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_pipe[1]),
            is_read_end: false,
            pipe_id: 4242,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_WRONLY,
        0,
    );
    let (_read_fd, write_fd) = dispatcher
        .install_fd_pair_at_or_above(4, read_open, write_open)
        .expect("install host pipe pair");

    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
    let outcome = dispatcher
        .dispatch_normalized(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                76,
                SyscallArgs::from([
                    in_fd as u64,
                    0,
                    write_fd as u64,
                    0,
                    contents.len() as u64,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            None,
        )
        .expect("splice is a claimed syscall")
        .expect("splice must not be a fatal DispatchError");

    let DispatchOutcome::Returned { value } = outcome else {
        let _ = std::fs::remove_file(&path);
        panic!(
            "splice into a pipe must return a count, got {outcome:?}: a \
                 write(2)-style transfer that parks until every byte lands \
                 deadlocks a single-threaded guest"
        );
    };
    let moved = usize::try_from(value).expect("non-negative splice count");
    assert!(moved > 0, "splice moved nothing");
    assert!(
        moved < contents.len(),
        "expected a SHORT transfer bounded by the pipe, moved all {moved}"
    );

    // `off_in` was NULL, so the source's kernel offset must have advanced by
    // exactly what moved; otherwise the next iteration re-reads byte 0.
    let pos = unsafe { libc::lseek(host_fd, 0, libc::SEEK_CUR) };
    assert_eq!(
        pos, moved as i64,
        "a NULL off_in splice must advance the source offset"
    );

    let _ = std::fs::remove_file(&path);
}

/// Linux exposes splice-write support on the null and zero character devices:
/// a readable pipe may be drained directly into either writable device. LTP
/// splice09 exercises both paths; rejecting the synthetic descriptions before
/// the write route returns EINVAL and leaves both assertions red.
#[test]
fn splice_pipe_to_writable_null_and_zero_devices_consumes_bytes() {
    const SYS_OPENAT: u64 = 56;
    const SYS_CLOSE: u64 = 57;
    const SYS_PIPE2: u64 = 59;
    const SYS_READ: u64 = 63;
    const SYS_WRITE: u64 = 64;
    const SYS_SPLICE: u64 = 76;
    const PATH: u64 = 0x4000;
    const PAYLOAD: u64 = 0x4100;
    const PIPE_FDS: u64 = 0x4200;
    const BYTES: &[u8] = b"splice09";

    for device in [b"/dev/null\0".as_slice(), b"/dev/zero\0".as_slice()] {
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
        memory.write_bytes(PATH, device).unwrap();
        memory.write_bytes(PAYLOAD, BYTES).unwrap();

        let run = |dispatcher: &mut SyscallDispatcher,
                   memory: &mut LinearMemory,
                   nr: u64,
                   args: [u64; 6]| {
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(nr, SyscallArgs::from(args)),
                    memory,
                    &reporter,
                )
                .expect("dispatch")
        };

        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_PIPE2,
                [PIPE_FDS, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        let pair = memory.read_bytes(PIPE_FDS, 8).unwrap();
        let read_fd = i32::from_ne_bytes(pair[0..4].try_into().unwrap()) as u64;
        let write_fd = i32::from_ne_bytes(pair[4..8].try_into().unwrap()) as u64;

        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_WRITE,
                [write_fd, PAYLOAD, BYTES.len() as u64, 0, 0, 0],
            ),
            DispatchOutcome::returned_len_or_errno(BYTES.len()),
        );
        let device_fd = match run(
            &mut dispatcher,
            &mut memory,
            SYS_OPENAT,
            [LINUX_AT_FDCWD, PATH, LINUX_O_WRONLY, 0, 0, 0],
        ) {
            DispatchOutcome::Returned { value } => value as u64,
            other => panic!("open writable device failed: {other:?}"),
        };

        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_SPLICE,
                [read_fd, 0, device_fd, 0, BYTES.len() as u64, 0],
            ),
            DispatchOutcome::returned_len_or_errno(BYTES.len()),
        );
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_CLOSE,
                [write_fd, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_READ,
                [read_fd, PAYLOAD, BYTES.len() as u64, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );

        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_PIPE2,
                [PIPE_FDS, 0, 0, 0, 0, 0],
            ),
            DispatchOutcome::Returned { value: 0 },
        );
        let pair = memory.read_bytes(PIPE_FDS, 8).unwrap();
        let read_fd = i32::from_ne_bytes(pair[0..4].try_into().unwrap()) as u64;
        let write_fd = i32::from_ne_bytes(pair[4..8].try_into().unwrap()) as u64;
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_WRITE,
                [write_fd, PAYLOAD, BYTES.len() as u64, 0, 0, 0],
            ),
            DispatchOutcome::returned_len_or_errno(BYTES.len()),
        );
        let append_fd = match run(
            &mut dispatcher,
            &mut memory,
            SYS_OPENAT,
            [
                LINUX_AT_FDCWD,
                PATH,
                LINUX_O_WRONLY | LINUX_O_APPEND,
                0,
                0,
                0,
            ],
        ) {
            DispatchOutcome::Returned { value } => value as u64,
            other => panic!("open append device failed: {other:?}"),
        };
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_SPLICE,
                [read_fd, 0, append_fd, 0, BYTES.len() as u64, 0],
            ),
            DispatchOutcome::errno(LINUX_EINVAL),
        );

        let read_only_fd = match run(
            &mut dispatcher,
            &mut memory,
            SYS_OPENAT,
            [LINUX_AT_FDCWD, PATH, LINUX_O_RDONLY, 0, 0, 0],
        ) {
            DispatchOutcome::Returned { value } => value as u64,
            other => panic!("open read-only device failed: {other:?}"),
        };
        assert_eq!(
            run(
                &mut dispatcher,
                &mut memory,
                SYS_SPLICE,
                [read_fd, 0, read_only_fd, 0, BYTES.len() as u64, 0],
            ),
            DispatchOutcome::errno(LINUX_EBADF),
        );
    }
}

struct SpliceTestRig {
    dispatcher: SyscallDispatcher,
    memory: LinearMemory,
    reporter: CompatReporter,
}

impl SpliceTestRig {
    const SYS_FCNTL: u64 = 25;
    const SYS_OPENAT: u64 = 56;
    const SYS_CLOSE: u64 = 57;
    const SYS_PIPE2: u64 = 59;
    const SYS_READ: u64 = 63;
    const SYS_WRITE: u64 = 64;
    const SYS_SENDFILE: u64 = 71;
    const SYS_SPLICE: u64 = 76;
    const SYS_COPY_FILE_RANGE: u64 = 285;

    fn new(mem_size: usize) -> Self {
        Self {
            dispatcher: SyscallDispatcher::new(),
            memory: LinearMemory::new(0x4000, vec![0; mem_size]),
            reporter: CompatReporter::default(),
        }
    }

    fn run(&mut self, nr: u64, args: [u64; 6]) -> DispatchOutcome {
        self.dispatcher
            .dispatch(
                &self.dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(nr, SyscallArgs::from(args)),
                &mut self.memory,
                &self.reporter,
            )
            .expect("dispatch")
    }

    fn pipe2(&mut self, fds_addr: u64) -> (u64, u64) {
        assert_eq!(
            self.run(Self::SYS_PIPE2, [fds_addr, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
        );
        let pair = self.memory.read_bytes(fds_addr, 8).unwrap();
        let rfd = i32::from_ne_bytes(pair[0..4].try_into().unwrap()) as u64;
        let wfd = i32::from_ne_bytes(pair[4..8].try_into().unwrap()) as u64;
        (rfd, wfd)
    }

    fn open(&mut self, path_addr: u64, path: &[u8], flags: u64) -> u64 {
        self.memory.write_bytes(path_addr, path).unwrap();
        match self.run(
            Self::SYS_OPENAT,
            [LINUX_AT_FDCWD, path_addr, flags, 0, 0, 0],
        ) {
            DispatchOutcome::Returned { value } => value as u64,
            other => panic!("open {path:?} failed: {other:?}"),
        }
    }

    fn close(&mut self, fd: u64) {
        assert_eq!(
            self.run(Self::SYS_CLOSE, [fd, 0, 0, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
        );
    }
}

#[test]
fn final_pipe_description_close_disarms_fasync_registration() {
    const SYS_DUP: u64 = 23;

    carrick_signal_core::fasync::fasync_init();
    let mut rig = SpliceTestRig::new(0x10000);
    let (read_fd, write_fd) = rig.pipe2(0x4200);
    let pipe_id = rig
        .dispatcher
        .host_pipe_pipe_id(read_fd as i32)
        .expect("pipe id");
    if let Some(owner) = carrick_signal_core::fasync::lookup(pipe_id) {
        carrick_signal_core::fasync::disarm(pipe_id, owner.registration_id);
    }

    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_FCNTL,
            [read_fd, LINUX_F_SETOWN, 1, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 },
    );
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_FCNTL,
            [read_fd, LINUX_F_SETFL, LINUX_O_ASYNC, 0, 0, 0],
        ),
        DispatchOutcome::Returned { value: 0 },
    );
    assert!(carrick_signal_core::fasync::lookup(pipe_id).is_some());

    let alias = match rig.run(SYS_DUP, [read_fd, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("dup read end failed: {other:?}"),
    };
    rig.close(read_fd);
    assert!(
        carrick_signal_core::fasync::lookup(pipe_id).is_some(),
        "closing one dup must retain the description's registration",
    );
    rig.close(alias);
    assert_eq!(
        carrick_signal_core::fasync::lookup(pipe_id),
        None,
        "the final description close must reclaim its FASYNC slot",
    );
    rig.close(write_fd);
}

/// Splicing FROM readable synthetic character devices into a pipe write end:
/// - /dev/zero and /dev/full yield requested zero bytes (LTP splice08).
/// - /dev/null yields EOF (returns 0).
/// - /dev/random and /dev/urandom yield pseudo-random bytes of requested length.
#[test]
fn splice_synthetic_devices_to_pipe_transfers_bytes_or_eof() {
    let cases: &[(&[u8], usize, bool)] = &[
        (b"/dev/zero\0", 1009, true),
        (b"/dev/full\0", 2018, true),
        (b"/dev/null\0", 1009, false),
        (b"/dev/urandom\0", 64, false),
        (b"/dev/random\0", 64, false),
    ];

    for &(device_path, count, expect_zeroes) in cases {
        let mut rig = SpliceTestRig::new(0x10000);
        let (read_fd, write_fd) = rig.pipe2(0x4200);
        let dev_fd = rig.open(0x4000, device_path, LINUX_O_RDONLY);

        // 0-byte splice always returns 0 without consuming.
        assert_eq!(
            rig.run(SpliceTestRig::SYS_SPLICE, [dev_fd, 0, write_fd, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
        );

        // Nonzero splice from synthetic device to pipe.
        let expected_return = if device_path == b"/dev/null\0" {
            0
        } else {
            count as i64
        };
        assert_eq!(
            rig.run(
                SpliceTestRig::SYS_SPLICE,
                [dev_fd, 0, write_fd, 0, count as u64, 0]
            ),
            DispatchOutcome::Returned {
                value: expected_return
            },
        );

        // Read transferred bytes from the pipe to verify.
        if expected_return > 0 {
            assert_eq!(
                rig.run(
                    SpliceTestRig::SYS_READ,
                    [read_fd, 0x5000, count as u64, 0, 0, 0]
                ),
                DispatchOutcome::returned_len_or_errno(count),
            );
            let read_bytes = rig.memory.read_bytes(0x5000, count).unwrap();
            if expect_zeroes {
                assert!(read_bytes.iter().all(|&b| b == 0));
            }
        }

        rig.close(dev_fd);
        rig.close(read_fd);
        rig.close(write_fd);
    }
}

/// Splicing synthetic devices enforces open access mode, offset rules, and genuine pipe requirement:
/// - O_WRONLY synthetic device returns EBADF.
/// - Valid off_in pointer succeeds without altering offset in memory.
/// - Unmapped off_in pointer returns EFAULT.
/// - Splicing between two synthetic devices (no pipe) returns EINVAL.
#[test]
fn splice_synthetic_devices_access_mode_and_offset_rules() {
    let mut rig = SpliceTestRig::new(0x10000);
    let (_read_fd, write_fd) = rig.pipe2(0x4200);
    rig.memory
        .write_bytes(0x4300, &42u64.to_ne_bytes())
        .unwrap();

    // O_WRONLY device as source -> EBADF.
    let dev_wo = rig.open(0x4000, b"/dev/zero\0", LINUX_O_WRONLY);
    assert_eq!(
        rig.run(SpliceTestRig::SYS_SPLICE, [dev_wo, 0, write_fd, 0, 100, 0]),
        DispatchOutcome::errno(LINUX_EBADF),
    );

    // O_RDONLY device as source.
    let dev_ro = rig.open(0x4000, b"/dev/zero\0", LINUX_O_RDONLY);

    // Valid non-NULL off_in succeeds and does not modify the memory offset.
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_SPLICE,
            [dev_ro, 0x4300, write_fd, 0, 100, 0]
        ),
        DispatchOutcome::Returned { value: 100 },
    );
    let off_after = u64::from_ne_bytes(
        rig.memory
            .read_bytes(0x4300, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(off_after, 42);

    // Unmapped/faulty off_in returns EFAULT.
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_SPLICE,
            [dev_ro, 0xdeadbeef0000, write_fd, 0, 100, 0]
        ),
        DispatchOutcome::errno(LINUX_EFAULT),
    );

    // Splice between two synthetic devices (neither end is a pipe) returns EINVAL.
    let null_rw = rig.open(0x4020, b"/dev/null\0", LINUX_O_RDWR);
    assert_eq!(
        rig.run(SpliceTestRig::SYS_SPLICE, [dev_ro, 0, null_rw, 0, 100, 0]),
        DispatchOutcome::errno(LINUX_EINVAL),
    );
}

/// Splicing synthetic devices into a pipe respects pipe write room:
/// - Transfers only up to available room.
/// - Full pipe returns WaitOnFds under blocking mode, parking on pipe readiness and carrying slot authorities.
/// - Full pipe returns EAGAIN under nonblocking mode.
#[test]
fn splice_synthetic_devices_pipe_capacity_and_nonblocking() {
    let mut rig = SpliceTestRig::new(0x20000);
    let (_read_fd, write_fd) = rig.pipe2(0x4200);
    let dev_fd = rig.open(0x4000, b"/dev/zero\0", LINUX_O_RDONLY);

    // Splice 100 bytes into empty pipe.
    assert_eq!(
        rig.run(SpliceTestRig::SYS_SPLICE, [dev_fd, 0, write_fd, 0, 100, 0]),
        DispatchOutcome::Returned { value: 100 },
    );

    // Fill the pipe to capacity.
    let room = rig
        .dispatcher
        .splice_pipe_write_room(write_fd as i32)
        .unwrap_or(0);
    if room > 0 {
        assert_eq!(
            rig.run(
                SpliceTestRig::SYS_WRITE,
                [write_fd, 0x5000, room as u64, 0, 0, 0]
            ),
            DispatchOutcome::returned_len_or_errno(room),
        );
    }
    assert_eq!(
        rig.dispatcher.splice_pipe_write_room(write_fd as i32),
        Some(0),
        "full in-memory pipe must report zero room"
    );

    let (write_poll_fd, poll_events) = match &*rig
        .dispatcher
        .open_file(write_fd as i32)
        .expect("write file")
        .description
        .read()
        .expect("open description")
    {
        OpenDescription::PipeWriter { pipe, .. } => (
            pipe.write_poll_fd()
                .expect("pipe must have write poll fd")
                .raw(),
            libc::POLLIN,
        ),
        OpenDescription::HostPipe { host_fd, .. } => (host_fd.raw(), libc::POLLOUT),
        other => panic!("unexpected open description: {other:?}"),
    };

    let dev_authority = rig
        .dispatcher
        .captured_slot_authority(dev_fd as i32)
        .expect("dev authority");
    let pipe_authority = rig
        .dispatcher
        .captured_slot_authority(write_fd as i32)
        .expect("pipe authority");

    // Blocking splice on full pipe must return WaitOnFds parking on pipe readiness
    // and carrying both in and out slot authorities.
    let outcome = rig.run(SpliceTestRig::SYS_SPLICE, [dev_fd, 0, write_fd, 0, 100, 0]);
    let DispatchOutcome::WaitOnFds {
        fds,
        timeout,
        sig_mask,
        completion,
    } = outcome
    else {
        panic!("expected blocking splice on full pipe to return WaitOnFds, got {outcome:?}");
    };
    assert_eq!(timeout, None);
    assert_eq!(
        completion,
        FdWaitCompletion::Fd {
            on_timeout: LINUX_EAGAIN.guest_retval()
        }
    );
    assert_eq!(sig_mask, carrick_abi::WaitSigMask::NONE);
    assert_eq!(
        fds.first(),
        Some((write_poll_fd, poll_events)),
        "full pipe must park on pipe readiness fd"
    );
    let auths = fds.logical_authorities_for_test();
    assert!(
        auths.contains(&dev_authority),
        "WaitOnFds must contain input slot authority"
    );
    assert!(
        auths.contains(&pipe_authority),
        "WaitOnFds must contain output slot authority"
    );

    // Splicing with SPLICE_F_NONBLOCK into full pipe returns EAGAIN.
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_SPLICE,
            [
                dev_fd,
                0,
                write_fd,
                0,
                100,
                carrick_abi::LINUX_SPLICE_F_NONBLOCK
            ],
        ),
        DispatchOutcome::errno(LINUX_EAGAIN),
    );
}

/// sendfile and copy_file_range reject synthetic devices with EINVAL (no widening).
#[test]
fn sendfile_and_copy_file_range_reject_synthetic_device() {
    let mut rig = SpliceTestRig::new(0x10000);
    let (_read_fd, write_fd) = rig.pipe2(0x4200);
    let dev_fd = rig.open(0x4000, b"/dev/zero\0", LINUX_O_RDONLY);

    // copy_file_range rejects SyntheticDevice with EINVAL.
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_COPY_FILE_RANGE,
            [dev_fd, 0, write_fd, 0, 100, 0]
        ),
        DispatchOutcome::errno(LINUX_EINVAL),
    );

    // sendfile rejects SyntheticDevice with EINVAL.
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_SENDFILE,
            [write_fd, dev_fd, 0, 100, 0, 0]
        ),
        DispatchOutcome::errno(LINUX_EINVAL),
    );
}

#[test]
fn splice_pushback_keeps_large_stages_chunked() {
    let mut pushback = fs::SplicePushback::default();
    let bytes = vec![0x5a; 1024 * 1024];

    pushback.push_front(&bytes);

    assert_eq!(pushback.len(), bytes.len());
    assert_eq!(pushback.chunk_count_for_tests(), 1);

    let mut drained = Vec::new();
    pushback.take_into(4096, &mut drained);

    assert_eq!(drained, &bytes[..4096]);
    assert_eq!(pushback.len(), bytes.len() - 4096);
    assert_eq!(pushback.chunk_count_for_tests(), 1);
}

#[test]
fn splice_pushback_moves_owned_full_chunks_without_copy() {
    let mut pushback = fs::SplicePushback::default();
    let bytes = vec![0x33; 1024 * 1024];
    let ptr = bytes.as_ptr();

    pushback.push_back_owned(bytes);
    let drained = pushback.take_vec(1024 * 1024);

    assert_eq!(drained.as_ptr(), ptr);
    assert_eq!(drained.len(), 1024 * 1024);
    assert!(pushback.is_empty());
}

#[test]
fn vfs_open_fallthrough_does_not_build_open_context() {
    fd_helpers::reset_open_fd_numbers_calls();

    let dispatcher = SyscallDispatcher::new();
    let outcome = dispatcher.try_vfs_open(
        &dispatcher.exact_signal_context_for_test(),
        None,
        "/tmp/not-a-vfs-mount",
        LINUX_O_RDWR,
        0,
        0,
    );

    assert_eq!(outcome, VfsOpenAttempt::FallThrough);
    assert_eq!(
        fd_helpers::open_fd_numbers_calls(),
        0,
        "unmounted rootfs/overlay opens should fall through before building OpenContext"
    );
}

#[test]
fn bind_mount_rejects_o_directory_for_regular_file() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("target"), b"old").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        "/bind",
        Box::new(crate::vfs::BindVfs::new("/bind", host.path(), false)),
    );

    let before = dispatcher.open_fd_numbers();
    for flags in [
        crate::linux_abi::LINUX_O_PATH | LINUX_O_DIRECTORY,
        LINUX_O_WRONLY | LINUX_O_TRUNC | LINUX_O_DIRECTORY,
    ] {
        let outcome = dispatcher
            .open_at_path_string(
                &dispatcher.exact_signal_context_for_test(),
                None,
                OpenAtArgs {
                    dirfd: LINUX_AT_FDCWD,
                    path: "/bind/target",
                    flags,
                    mode: 0,
                },
                &reporter,
            )
            .unwrap();
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOTDIR));
        assert_eq!(dispatcher.open_fd_numbers(), before);
        assert_eq!(std::fs::read(host.path().join("target")).unwrap(), b"old");
    }
    let create = dispatcher
        .open_at_path_string(
            &dispatcher.exact_signal_context_for_test(),
            None,
            OpenAtArgs {
                dirfd: LINUX_AT_FDCWD,
                path: "/bind/missing",
                flags: LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_DIRECTORY,
                mode: 0o600,
            },
            &reporter,
        )
        .unwrap();
    assert_eq!(create, DispatchOutcome::errno(LINUX_EINVAL));
    assert!(!host.path().join("missing").exists());

    assert!(matches!(
        dispatcher
            .open_at_path_string(
                &dispatcher.exact_signal_context_for_test(),
                None,
                OpenAtArgs {
                    dirfd: LINUX_AT_FDCWD,
                    path: "/bind",
                    flags: crate::linux_abi::LINUX_O_PATH | LINUX_O_DIRECTORY,
                    mode: 0,
                },
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { .. }
    ));
}

#[test]
fn f_add_seals_waits_for_alias_dispatch_and_publishes_under_same_exclusion() {
    let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
    let common = std::sync::Arc::new(crate::kernel::DescriptionCommon::new(LINUX_O_RDWR));
    common.set_seals(Some(0));
    let description = std::sync::Arc::new(RwLock::new(OpenDescription::SyntheticFile {
        base: OpenDescriptionBase::new(0),
        path: "/memfd:test".to_string(),
        contents: Vec::new(),
        offset: 0,
    }));
    let fd = dispatcher
        .install_fd_at_or_above(
            3,
            OpenFile::from_open_description_with_common(
                std::sync::Arc::clone(&description),
                std::sync::Arc::clone(&common),
                0,
            ),
        )
        .expect("install sealable fd");

    dispatcher.with_host_alias_dispatch_for_test(|guard| {
        let sibling = std::sync::Arc::clone(&dispatcher);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let reporter = CompatReporter::default();
            let mut memory = LinearMemory::new(0x1000, vec![0; 0x1000]);
            started_tx.send(()).expect("report F_ADD_SEALS start");
            let outcome = sibling
                .dispatch_normalized_mutation_for_test(
                    &sibling.capture_one_task_context().unwrap(),
                    SyscallRequest::new(
                        25,
                        SyscallArgs::from([
                            fd as u64,
                            LINUX_F_ADD_SEALS,
                            u64::from(carrick_abi::LinuxMemfdSeals::SHRINK.bits()),
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                    None,
                )
                .expect("fcntl is a claimed syscall")
                .expect("F_ADD_SEALS must not be a fatal DispatchError");
            outcome_tx
                .send(outcome)
                .expect("report F_ADD_SEALS outcome");
        });

        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("F_ADD_SEALS thread reached dispatch");
        assert!(
            outcome_rx
                .recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "F_ADD_SEALS raced an in-flight alias dispatch"
        );
        assert_eq!(
            common.seals(),
            Some(carrick_abi::LinuxMemfdSeals::empty().bits())
        );

        drop(guard);

        assert_eq!(
            outcome_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("F_ADD_SEALS resumes after alias dispatch exits"),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            common.seals(),
            Some(carrick_abi::LinuxMemfdSeals::SHRINK.bits())
        );
        thread.join().expect("join F_ADD_SEALS thread");
    });
}

#[test]
fn bind_mount_setxattr_reports_unsupported_instead_of_missing() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("target"), b"payload").unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.register_mount(
        "/bind",
        Box::new(crate::vfs::BindVfs::new("/bind", host.path(), false)),
    );
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/bind/target\0").unwrap();
    memory.write_bytes(0x4100, b"security.test\0").unwrap();
    memory.write_bytes(0x4200, b"x").unwrap();

    let target = XattrTarget::Path {
        path: GuestPtr(0x4000),
        follow: true,
    };
    let outcome = dispatcher
        .setxattr(
            &mut memory,
            target,
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            0,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOTSUP));

    let invalid = dispatcher
        .setxattr(
            &mut memory,
            target,
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            (crate::linux_abi::LINUX_XATTR_CREATE | crate::linux_abi::LINUX_XATTR_REPLACE) as u64,
        )
        .unwrap();
    assert_eq!(invalid, DispatchOutcome::errno(LINUX_EINVAL));

    let mut readonly = SyscallDispatcher::new();
    readonly.register_mount(
        "/bind",
        Box::new(crate::vfs::BindVfs::new("/bind", host.path(), true)),
    );
    let readonly_result = readonly
        .setxattr(
            &mut memory,
            target,
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            0,
        )
        .unwrap();
    assert_eq!(readonly_result, DispatchOutcome::errno(LINUX_EROFS));

    memory.write_bytes(0x4000, b"/dev/null\0").unwrap();
    memory.write_bytes(0x4100, b"user.test\0").unwrap();
    let device = SyscallDispatcher::new()
        .setxattr(
            &mut memory,
            XattrTarget::Path {
                path: GuestPtr(0x4000),
                follow: true,
            },
            GuestPtr(0x4100),
            GuestPtr(0x4200),
            1,
            0,
        )
        .unwrap();
    assert_eq!(device, DispatchOutcome::errno(LINUX_EPERM));
}

#[test]
fn sync_file_range_rejects_synthetic_character_device_with_espipe() {
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/dev/null\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(56, SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                // sync_file_range(fd, 0, 1, SYNC_FILE_RANGE_WAIT_AFTER)
                SyscallRequest::new(84, SyscallArgs::from([3, 0, 1, 4, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(LINUX_ESPIPE)
    );
}

#[test]
fn memory_file_open_does_not_duplicate_path_record_for_proc_fd() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend
        .set_file_contents("/regular.bin", b"payload".to_vec())
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/regular.bin\0").unwrap();

    let context = dispatcher.capture_one_task_context().unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(56, SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    memory.write_bytes(0x4100, b"/proc/self/fd/3\0").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    78,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4100, 0x4200, 64, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 12 }
    );
    assert_eq!(
        memory.read_bytes(0x4200, 12).unwrap(),
        b"/regular.bin".to_vec()
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn rlimit_fsize_straddling_regular_write_returns_only_the_limit_prefix() {
    let backend = crate::fs_backend::MemoryBackend::new();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let context = dispatcher.capture_one_task_context().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/fsize-limit\0").unwrap();
    memory
        .write_bytes(
            0x4100,
            &[10_u64.to_le_bytes(), 10_u64.to_le_bytes()].concat(),
        )
        .unwrap();
    memory
        .write_bytes(0x4200, b"abcdefghijklmnopqrstuvwxyz")
        .unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    261,
                    SyscallArgs::from([0, carrick_abi::LINUX_RLIMIT_FSIZE, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let fd = match dispatcher
        .dispatch(
            &context,
            SyscallRequest::new(
                56,
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    0x4000,
                    LINUX_O_CREAT | LINUX_O_WRONLY,
                    0o644,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("open regular file failed: {other:?}"),
    };

    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(64, SyscallArgs::from([fd as u64, 0x4200, 26, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 10 }
    );
    let open = dispatcher
        .open_file(fd)
        .expect("created regular file remains open");
    let description = open.description.read().expect("open description");
    let OpenDescription::File { contents, .. } = &*description else {
        panic!("expected in-memory regular-file description");
    };
    assert_eq!(contents.len().unwrap(), 10);
    let mut buf = vec![0u8; 10];
    assert_eq!(contents.read_at(0, &mut buf).unwrap(), 10);
    assert_eq!(buf, b"abcdefghij");
}

/// `close(2)` must retire the descriptor's `fd_open_paths` entry.
///
/// Only one close path used to clear it, so a path-opened descriptor left
/// a permanent entry claiming a freed fd number. The K1 coherent snapshot
/// refuses such a table, which is how this surfaced: a live
/// `carrick debug hvpatch-kernel` against `sleep` under HVPatch reported
/// "file-table open-path index names no live slot" with the orphan
/// `(3, "/usr/lib/locale/C.utf8/LC_CTYPE")` — glibc's locale file, opened,
/// mapped, and closed during startup.
#[test]
fn close_retires_the_fd_open_path_entry() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend
        .set_file_contents("/locale.bin", b"payload".to_vec())
        .unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/locale.bin\0").unwrap();

    let context = dispatcher.capture_one_task_context().unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(56, SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0]),),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert!(
        context
            .resources()
            .files()
            .read_fd_open_paths()
            .contains_key(&3),
        "a path-opened host descriptor must record its open path"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        context.resources().files().read_fd_open_paths().is_empty(),
        "close must retire the open-path entry; a freed fd cannot own a path"
    );
}

#[test]
fn openat2_resolve_no_symlinks_rejects_link_path() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend
        .set_file_contents("/target", b"payload".to_vec())
        .unwrap();
    backend.symlink("target", "/link").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/link\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_NO_SYMLINKS,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP)
    );
}

#[test]
fn openat2_rejects_unknown_and_invalid_opath_flag_combinations() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend
        .set_file_contents("/regular", b"payload".to_vec())
        .unwrap();
    backend.make_dir("/empty").unwrap();

    let invalid_cases = [
        (
            "O_PATH|O_RDWR",
            "/regular",
            crate::linux_abi::LINUX_O_PATH | LINUX_O_RDWR,
            0,
        ),
        (
            "O_PATH|O_WRONLY",
            "/regular",
            crate::linux_abi::LINUX_O_PATH | LINUX_O_WRONLY,
            0,
        ),
        (
            "O_PATH|O_CREAT",
            "/regular",
            crate::linux_abi::LINUX_O_PATH | LINUX_O_CREAT,
            0o644,
        ),
        (
            "O_PATH|O_TRUNC",
            "/regular",
            crate::linux_abi::LINUX_O_PATH | LINUX_O_TRUNC,
            0,
        ),
        (
            "O_PATH|O_TMPFILE|O_WRONLY",
            "/empty",
            crate::linux_abi::LINUX_O_PATH
                | crate::linux_abi::LINUX_O_TMPFILE
                | LINUX_O_DIRECTORY
                | LINUX_O_WRONLY,
            0o644,
        ),
        ("unknown flag bit", "/regular", 1_u64 << 62, 0),
    ];

    for (label, path, flags, mode) in invalid_cases {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend.clone()));
        let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        memory.write_bytes(0x4000, &path_bytes).unwrap();

        assert_eq!(
            dispatch_openat2_for_test(
                &mut dispatcher,
                &mut memory,
                LINUX_AT_FDCWD,
                0x4000,
                flags,
                mode,
                0,
            )
            .unwrap(),
            DispatchOutcome::errno(LINUX_EINVAL),
            "{label}"
        );
    }
}

#[test]
fn openat2_resolve_beneath_rejects_dotdot_escape() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/root").unwrap();
    backend.make_dir("/root/dir").unwrap();
    backend
        .set_file_contents("/root/outside", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    memory.write_bytes(0x4000, b"/root/dir\0").unwrap();
    let dirfd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    0x4000,
                    LINUX_O_RDONLY | crate::linux_abi::LINUX_O_DIRECTORY,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("directory open failed: {other:?}"),
    };
    memory.write_bytes(0x4100, b"../outside\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            dirfd,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_BENEATH,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV)
    );
}

#[test]
fn openat2_resolve_no_xdev_rejects_proc_mount_crossing() {
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/self/status\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_NO_XDEV,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV)
    );
}

#[test]
fn openat2_resolve_no_magiclinks_rejects_proc_fd_reopen() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend
        .set_file_contents("/regular.bin", b"payload".to_vec())
        .unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/regular.bin\0").unwrap();
    let fd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_O_RDONLY, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value,
        other => panic!("regular open failed: {other:?}"),
    };
    let proc_fd_path = format!("/proc/self/fd/{fd}\0");
    memory.write_bytes(0x4100, proc_fd_path.as_bytes()).unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_NO_MAGICLINKS,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ELOOP)
    );
}

#[test]
fn openat2_resolve_in_root_rejects_absolute_escape() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/root").unwrap();
    backend
        .set_file_contents("/outside", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    memory.write_bytes(0x4000, b"/root\0").unwrap();
    let dirfd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    0x4000,
                    LINUX_O_RDONLY | crate::linux_abi::LINUX_O_DIRECTORY,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("root dir open failed: {other:?}"),
    };
    memory.write_bytes(0x4100, b"/outside\0").unwrap();

    assert_eq!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            dirfd,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_IN_ROOT,
        )
        .unwrap(),
        DispatchOutcome::errno(crate::linux_abi::LINUX_ENOENT)
    );
}

#[test]
fn openat2_resolve_in_root_clamps_parent_components_at_dirfd() {
    let backend = crate::fs_backend::MemoryBackend::new();
    backend.make_dir("/root").unwrap();
    backend
        .set_file_contents("/root/regfile", b"payload".to_vec())
        .unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    memory.write_bytes(0x4000, b"/root\0").unwrap();
    let dirfd = match dispatcher
        .dispatch(
            &dispatcher.capture_one_task_context().unwrap(),
            SyscallRequest::new(
                56,
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    0x4000,
                    LINUX_O_RDONLY | crate::linux_abi::LINUX_O_DIRECTORY,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("root dir open failed: {other:?}"),
    };
    memory.write_bytes(0x4100, b"../../regfile\0").unwrap();

    assert!(matches!(
        dispatch_openat2_for_test(
            &mut dispatcher,
            &mut memory,
            dirfd,
            0x4100,
            LINUX_O_RDONLY,
            0,
            LINUX_RESOLVE_IN_ROOT,
        )
        .unwrap(),
        DispatchOutcome::Returned { value } if value >= 0
    ));
}

const LINUX_RESOLVE_NO_XDEV: u64 = 0x01;
const LINUX_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const LINUX_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const LINUX_RESOLVE_BENEATH: u64 = 0x08;
const LINUX_RESOLVE_IN_ROOT: u64 = 0x10;

fn dispatch_openat2_for_test(
    dispatcher: &mut SyscallDispatcher,
    memory: &mut LinearMemory,
    dirfd: u64,
    path_addr: u64,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> Result<DispatchOutcome, DispatchError> {
    const HOW_ADDR: u64 = 0x4f00;
    memory.write_bytes(HOW_ADDR, &flags.to_le_bytes()).unwrap();
    memory
        .write_bytes(HOW_ADDR + 8, &mode.to_le_bytes())
        .unwrap();
    memory
        .write_bytes(HOW_ADDR + 16, &resolve.to_le_bytes())
        .unwrap();
    dispatcher.dispatch(
        &dispatcher.capture_one_task_context().unwrap(),
        SyscallRequest::new(
            437,
            SyscallArgs::from([
                dirfd,
                path_addr,
                HOW_ADDR,
                crate::linux_abi::LINUX_OPEN_HOW_SIZE,
                0,
                0,
            ]),
        ),
        memory,
        &CompatReporter::default(),
    )
}

#[test]
fn hvpatch_ofd_locks_conflict_with_posix_and_other_ofd() {
    let locks = LogicalRecordLocks::default();
    let file = LeaseFileId::Path("/test-ofd".to_owned());
    let posix = LogicalRecordLockRequest {
        file: file.clone(),
        owner: LogicalRecordLockOwner::Process {
            pid: 100,
            serial: 1,
        },
        range: LogicalRecordLockRange { start: 0, end: 50 },
        write: true,
    };
    let ofd1 = LogicalRecordLockRequest {
        file: file.clone(),
        owner: LogicalRecordLockOwner::Ofd(0x1000),
        range: LogicalRecordLockRange { start: 0, end: 50 },
        write: true,
    };
    let ofd2 = LogicalRecordLockRequest {
        file: file.clone(),
        owner: LogicalRecordLockOwner::Ofd(0x2000),
        range: LogicalRecordLockRange { start: 0, end: 50 },
        write: false,
    };

    assert_eq!(locks.try_set(posix.clone()), Ok(()));
    // OFD lock conflicts with POSIX lock
    assert_eq!(locks.try_set(ofd1.clone()), Err(LINUX_EAGAIN));

    // Release POSIX lock
    locks.unlock(&posix.file, posix.owner, posix.range);

    // OFD1 acquires exclusive
    assert_eq!(locks.try_set(ofd1.clone()), Ok(()));
    // OFD2 read lock conflicts with OFD1 write lock
    assert_eq!(locks.try_set(ofd2.clone()), Err(LINUX_EAGAIN));

    // Release OFD1 via release_ofd
    locks.release_ofd(&file, 0x1000);
    // Now OFD2 can acquire
    assert_eq!(locks.try_set(ofd2.clone()), Ok(()));
}

#[test]
fn hvpatch_flock_shared_and_exclusive_semantics() {
    let locks = LogicalRecordLocks::default();
    let file = LeaseFileId::Path("/test-flock".to_owned());

    // OFD 1 and OFD 2 acquire shared flock
    assert_eq!(locks.try_flock(file.clone(), 0x1000, false), Ok(()));
    assert_eq!(locks.try_flock(file.clone(), 0x2000, false), Ok(()));

    // OFD 3 tries exclusive flock -> conflicts
    assert_eq!(
        locks.try_flock(file.clone(), 0x3000, true),
        Err(LINUX_EAGAIN)
    );

    // Unlock OFD 1 and OFD 2
    locks.unlock_flock(&file, 0x1000);
    locks.unlock_flock(&file, 0x2000);

    // OFD 3 acquires exclusive flock
    assert_eq!(locks.try_flock(file.clone(), 0x3000, true), Ok(()));

    // OFD 1 tries shared -> conflicts
    assert_eq!(
        locks.try_flock(file.clone(), 0x1000, false),
        Err(LINUX_EAGAIN)
    );

    // Release OFD 3
    locks.release_ofd(&file, 0x3000);

    // Now OFD 1 can acquire exclusive
    assert_eq!(locks.try_flock(file.clone(), 0x1000, true), Ok(()));
}

#[test]
fn splice_block_captures_output_slot_and_rejects_same_number_reuse() {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().expect("context");
    let files = context.resources().files();
    let ids = crate::kernel::ObjectIdRegistry::new();
    let input_number = crate::kernel::FileSlotNumber::for_open_fd(7).expect("fd 7");
    files.install(
        input_number,
        Arc::new(crate::kernel::FileDescription::regular(
            ids.file_description_id().expect("old input description"),
        )),
        false,
    );
    let number = crate::kernel::FileSlotNumber::for_open_fd(8).expect("fd 8");
    files.install(
        number,
        Arc::new(crate::kernel::FileDescription::regular(
            ids.file_description_id().expect("old description"),
        )),
        false,
    );
    let outcome = super::super::resources::with_captured_resources(&context, || {
        dispatcher.complete_wait_fd_authority(
            dispatcher.splice_host_output_wait(8, -1, libc::POLLOUT, None, false),
            &files,
            [7, 8],
        )
    });
    let authorities = match outcome {
        DispatchOutcome::WaitOnFds { fds, .. } => {
            assert_eq!(fds.logical_authorities_for_test().len(), 2);
            fds.logical_authorities_for_test().to_vec()
        }
        other => panic!("expected splice wait, got {other:?}"),
    };
    files.install(
        input_number,
        Arc::new(crate::kernel::FileDescription::regular(
            ids.file_description_id()
                .expect("successor input description"),
        )),
        false,
    );
    assert!(
        authorities
            .iter()
            .any(|authority| !files.validate_slot_authority(*authority)),
        "input reuse invalidates the blocked splice while output stays stable"
    );
}

#[test]
fn threaded_dispatch_synthetic_device_write_routes_without_unhandled_syscall() {
    let mut dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().expect("task context");
    let reporter = CompatReporter::default();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(2200));
    let futex = crate::thread::FutexTable::new();
    let mut memory = LinearMemory::new(0x4000, vec![0u8; 0x1000]);

    const PATH_NULL: u64 = 0x4000;
    const PATH_FULL: u64 = 0x4020;
    const PAYLOAD_ADDR: u64 = 0x4100;
    const PAYLOAD: &[u8] = b"cpython cgi devnull write test";

    memory.write_bytes(PATH_NULL, b"/dev/null\0").unwrap();
    memory.write_bytes(PATH_FULL, b"/dev/full\0").unwrap();
    memory.write_bytes(PAYLOAD_ADDR, PAYLOAD).unwrap();

    let open_null = dispatcher
        .dispatch(
            &context,
            SyscallRequest::new(
                56, // SYS_OPENAT
                SyscallArgs::from([
                    LINUX_AT_FDCWD,
                    PATH_NULL,
                    LINUX_O_WRONLY | LINUX_O_APPEND,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("openat /dev/null");
    let null_fd = match open_null {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected openat /dev/null to return fd, got {other:?}"),
    };

    let write_null_outcome = dispatcher
        .dispatch_threaded(
            &context,
            SyscallRequest::new(
                64, // SYS_WRITE
                SyscallArgs::from([null_fd as u64, PAYLOAD_ADDR, PAYLOAD.len() as u64, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            registry.main_tid(),
            &registry,
            &futex,
        )
        .expect("dispatch_threaded write /dev/null");

    assert_eq!(
        write_null_outcome,
        DispatchOutcome::returned_len_or_errno(PAYLOAD.len())
    );

    let open_full = dispatcher
        .dispatch(
            &context,
            SyscallRequest::new(
                56, // SYS_OPENAT
                SyscallArgs::from([LINUX_AT_FDCWD, PATH_FULL, LINUX_O_WRONLY, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("openat /dev/full");
    let full_fd = match open_full {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected openat /dev/full to return fd, got {other:?}"),
    };

    let write_full_outcome = dispatcher
        .dispatch_threaded(
            &context,
            SyscallRequest::new(
                64, // SYS_WRITE
                SyscallArgs::from([full_fd as u64, PAYLOAD_ADDR, PAYLOAD.len() as u64, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
            registry.main_tid(),
            &registry,
            &futex,
        )
        .expect("dispatch_threaded write /dev/full");

    assert_eq!(write_full_outcome, DispatchOutcome::errno(LINUX_ENOSPC));

    let report = reporter.finish();
    assert!(
        report.unhandled_syscalls.is_empty(),
        "expected no unhandled syscalls, but found: {:?}",
        report.unhandled_syscalls
    );
}

struct TestInMemoryPipe {
    dispatcher: SyscallDispatcher,
    pipe: PipeRef,
    write_fd: i32,
    _read_fd: i32,
}

impl TestInMemoryPipe {
    fn new(pipe_id: u64, capacity: usize) -> Self {
        let dispatcher = SyscallDispatcher::new();
        let pipe = Arc::new(PipeInner::new_connected(pipe_id, capacity));
        let mut read_base = OpenDescriptionBase::new(LINUX_O_RDONLY);
        read_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
        let mut write_base = OpenDescriptionBase::new(LINUX_O_WRONLY);
        write_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));

        let read_open = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::PipeReader {
                base: read_base,
                pipe: Arc::clone(&pipe),
            })),
            LINUX_O_RDONLY,
            0,
        );
        let write_open = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::PipeWriter {
                base: write_base,
                pipe: Arc::clone(&pipe),
            })),
            LINUX_O_WRONLY,
            0,
        );
        let (_read_fd, write_fd) = dispatcher
            .install_fd_pair_at_or_above(3, read_open, write_open)
            .expect("install in-memory pipe pair");
        Self {
            dispatcher,
            pipe,
            write_fd,
            _read_fd,
        }
    }

    fn fill(&self, bytes: usize) {
        let mut state = self.pipe.state.lock();
        state.buffer.extend(vec![0x7f; bytes]);
        self.pipe.update_readiness_locked(&state);
    }

    fn dispatch_vmsplice(&self, payload_len: usize, flags: u64) -> DispatchOutcome {
        const SYS_VMSPLICE: u64 = 75;
        const IOV_ADDR: u64 = 0x1000;
        const PAYLOAD_ADDR: u64 = 0x2000;

        let mut memory = LinearMemory::new(0x1000, vec![0; PAYLOAD_ADDR as usize + payload_len]);
        let iov = LinuxIovec {
            iov_base: PAYLOAD_ADDR,
            iov_len: payload_len as u64,
        };
        write_kernel_struct_raw(&mut memory, IOV_ADDR, &iov).expect("write iovec");
        let payload = vec![0x5au8; payload_len];
        memory
            .write_bytes(PAYLOAD_ADDR, &payload)
            .expect("write payload");

        let reporter = CompatReporter::default();
        self.dispatcher
            .dispatch_normalized(
                &self.dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_VMSPLICE,
                    SyscallArgs::from([self.write_fd as u64, IOV_ADDR, 1, flags, 0, 0]),
                ),
                &mut memory,
                &reporter,
                None,
            )
            .expect("vmsplice is a claimed syscall")
            .expect("vmsplice must not be a fatal DispatchError")
    }
}

#[test]
fn vmsplice_in_memory_pipe_writer_is_bounded_by_available_capacity() {
    let test_pipe = TestInMemoryPipe::new(1001, 65536);

    // Exact room-selection seam check:
    assert_eq!(
        test_pipe
            .dispatcher
            .splice_pipe_write_room(test_pipe.write_fd),
        Some(65536),
        "in-memory pipe writer must report its available capacity as room"
    );

    // Gather 128 KiB into a 64 KiB pipe: transfers at most available room (64 KiB)
    // and immediately returns a short count rather than blocking.
    let outcome = test_pipe.dispatch_vmsplice(128 * 1024, 0);
    assert_eq!(outcome, DispatchOutcome::Returned { value: 65536 });
    assert_eq!(test_pipe.pipe.buffered_bytes(), 65536);
}

#[test]
fn vmsplice_in_memory_pipe_writer_full_nonblocking_returns_eagain() {
    let test_pipe = TestInMemoryPipe::new(1002, 65536);
    test_pipe.fill(65536);
    assert_eq!(
        test_pipe
            .dispatcher
            .splice_pipe_write_room(test_pipe.write_fd),
        Some(0),
        "full in-memory pipe must report zero room"
    );

    let outcome = test_pipe.dispatch_vmsplice(4096, carrick_abi::LinuxSpliceFlags::NONBLOCK.bits());
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EAGAIN));
}

#[test]
fn vmsplice_in_memory_pipe_writer_full_blocking_parks_on_write_readiness_pollin() {
    let test_pipe = TestInMemoryPipe::new(1003, 65536);
    test_pipe.fill(65536);
    let write_poll_fd = test_pipe
        .pipe
        .write_poll_fd()
        .expect("pipe must have write poll fd")
        .raw();

    assert_eq!(
        test_pipe
            .dispatcher
            .splice_pipe_write_room(test_pipe.write_fd),
        Some(0),
        "full in-memory pipe must report zero room"
    );

    let outcome = test_pipe.dispatch_vmsplice(4096, 0);
    let DispatchOutcome::WaitOnFds {
        fds,
        timeout,
        sig_mask,
        completion,
    } = outcome
    else {
        panic!("expected blocking vmsplice on full pipe to park on WaitOnFds, got {outcome:?}");
    };

    assert_eq!(timeout, None);
    assert_eq!(
        completion,
        FdWaitCompletion::Fd {
            on_timeout: LINUX_EAGAIN.guest_retval()
        }
    );
    assert_eq!(sig_mask, carrick_abi::WaitSigMask::NONE);
    assert_eq!(
        fds.first(),
        Some((write_poll_fd, libc::POLLIN)),
        "full pipe must park on write_poll_fd with POLLIN"
    );

    // Verify readiness pipe state: full pipe is not readable (no byte in readiness pipe)
    let mut poll_fd_struct = libc::pollfd {
        fd: write_poll_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll_fd_struct, 1, 0) }, 0);

    // Free PIPE_BUF bytes from reader; readiness pipe must now be signaled
    let PipeDrain::Bytes(drained) = take_pipe_bytes(&test_pipe.pipe, PIPE_BUF) else {
        panic!("drain pipe bytes");
    };
    assert_eq!(drained.len(), PIPE_BUF);

    let ready_after_drain = unsafe { libc::poll(&mut poll_fd_struct, 1, 0) };
    assert_eq!(
        ready_after_drain, 1,
        "pipe must become write-ready after reader drains PIPE_BUF"
    );
    assert_ne!(poll_fd_struct.revents & libc::POLLIN, 0);
}

struct TestPipePair {
    dispatcher: SyscallDispatcher,
    in_pipe: PipeRef,
    in_read_fd: i32,
    #[allow(dead_code)]
    in_write_fd: i32,
    out_pipe: PipeRef,
    #[allow(dead_code)]
    out_read_fd: i32,
    out_write_fd: i32,
}

impl TestPipePair {
    fn new(in_cap: usize, out_cap: usize) -> Self {
        Self::with_flags(in_cap, 0, out_cap, 0)
    }

    fn with_flags(in_cap: usize, in_flags: u64, out_cap: usize, out_flags: u64) -> Self {
        let dispatcher = SyscallDispatcher::new();
        let in_pipe = Arc::new(PipeInner::new_connected(2001, in_cap));
        let out_pipe = Arc::new(PipeInner::new_connected(2002, out_cap));

        let make_pair = |pipe: &PipeRef, r_flags, w_flags| {
            let desc = |flags, is_reader| {
                let mut base = OpenDescriptionBase::new(flags);
                base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
                let d = if is_reader {
                    OpenDescription::PipeReader {
                        base,
                        pipe: Arc::clone(pipe),
                    }
                } else {
                    OpenDescription::PipeWriter {
                        base,
                        pipe: Arc::clone(pipe),
                    }
                };
                OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(d)),
                    flags,
                    0,
                )
            };
            dispatcher
                .install_fd_pair_at_or_above(
                    3,
                    desc(LINUX_O_RDONLY | r_flags, true),
                    desc(LINUX_O_WRONLY | w_flags, false),
                )
                .expect("install pipe")
        };

        let (in_read_fd, in_write_fd) = make_pair(&in_pipe, in_flags, 0);
        let (out_read_fd, out_write_fd) = make_pair(&out_pipe, 0, out_flags);
        Self {
            dispatcher,
            in_pipe,
            in_read_fd,
            in_write_fd,
            out_pipe,
            out_read_fd,
            out_write_fd,
        }
    }

    fn fill_in(&self, bytes: &[u8]) {
        let mut s = self.in_pipe.state.lock();
        s.buffer.extend(bytes);
        self.in_pipe.update_readiness_locked(&s);
    }

    fn fill_out(&self, bytes: usize) {
        let mut s = self.out_pipe.state.lock();
        s.buffer.extend(vec![0x7f; bytes]);
        self.out_pipe.update_readiness_locked(&s);
    }

    fn dispatch_tee(&self, in_fd: i32, out_fd: i32, len: u64, flags: u64) -> DispatchOutcome {
        let mut mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let rep = CompatReporter::default();
        let args = SyscallArgs::from([in_fd as u64, out_fd as u64, len, flags, 0, 0]);
        self.dispatcher
            .dispatch_normalized(
                &self.dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(77, args),
                &mut mem,
                &rep,
                None,
            )
            .expect("tee claimed")
            .expect("tee outcome")
    }
}

fn assert_wait_on(outcome: DispatchOutcome, expected_fd: i32, events: i16) {
    match outcome {
        DispatchOutcome::WaitOnFds {
            fds,
            timeout,
            sig_mask,
            completion,
        } => {
            assert_eq!(timeout, None);
            assert_eq!(
                completion,
                FdWaitCompletion::Fd {
                    on_timeout: LINUX_EAGAIN.guest_retval()
                }
            );
            assert_eq!(sig_mask, carrick_abi::WaitSigMask::NONE);
            assert_eq!(fds.first(), Some((expected_fd, events)));
        }
        other => panic!("expected WaitOnFds for fd {expected_fd}, got {other:?}"),
    }
}

#[test]
fn tee_in_memory_basic_non_consuming_copy() {
    let pair = TestPipePair::new(65536, 65536);
    let payload: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    pair.fill_in(&payload);

    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, 0),
        DispatchOutcome::Returned { value: 1024 }
    );

    let tid = crate::thread::ThreadId::synthetic_for_tests(10);
    let mut dest_buf = vec![0u8; 1024];
    assert_eq!(
        read_pipe_bytes(&mut dest_buf, &pair.out_pipe, 0, tid),
        Ok(1024)
    );
    assert_eq!(dest_buf, payload);

    let mut src_buf = vec![0u8; 1024];
    assert_eq!(
        read_pipe_bytes(&mut src_buf, &pair.in_pipe, 0, tid),
        Ok(1024)
    );
    assert_eq!(src_buf, payload);

    // Zero-length returns 0
    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 0, 0),
        DispatchOutcome::Returned { value: 0 }
    );

    // Short transfer bounded by available room
    let small_pair = TestPipePair::new(65536, 4096);
    small_pair.fill_in(&vec![0x33u8; 4096]);
    small_pair.fill_out(3072);
    assert_eq!(
        small_pair.dispatch_tee(small_pair.in_read_fd, small_pair.out_write_fd, 4096, 0),
        DispatchOutcome::Returned { value: 1024 }
    );
    assert_eq!(small_pair.out_pipe.buffered_bytes(), 4096);
    assert_eq!(small_pair.in_pipe.buffered_bytes(), 4096);
}

#[test]
fn tee_in_memory_validation_and_same_pipe_precedence() {
    let pair = TestPipePair::new(65536, 65536);
    pair.fill_in(&[0x11; 512]);

    assert_eq!(
        pipe::tee_in_memory_pipes(&pair.in_pipe, &pair.in_pipe, 1024),
        pipe::InMemoryTeeOutcome::SamePipe
    );
    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.in_write_fd, 1024, 0),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.in_read_fd, 1024, 0),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 512, 0xdead_beef),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_read_fd, 512, 0),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    assert_eq!(
        pair.dispatch_tee(pair.in_write_fd, pair.out_write_fd, 512, 0),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
}

#[test]
fn tee_in_memory_empty_source_backpressure_and_eof() {
    let pair = TestPipePair::new(65536, 65536);
    let in_poll_fd = pair.in_pipe.read_poll_fd().expect("poll fd").raw();
    let nb_flags = carrick_abi::LinuxSpliceFlags::NONBLOCK.bits();

    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, nb_flags),
        DispatchOutcome::errno(LINUX_EAGAIN)
    );
    assert_wait_on(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, 0),
        in_poll_fd,
        libc::POLLIN,
    );

    // O_NONBLOCK on descriptor
    let nb_pair = TestPipePair::with_flags(65536, LINUX_O_NONBLOCK, 65536, 0);
    assert_eq!(
        nb_pair.dispatch_tee(nb_pair.in_read_fd, nb_pair.out_write_fd, 1024, 0),
        DispatchOutcome::errno(LINUX_EAGAIN)
    );

    // EOF: writers = 0
    pair.in_pipe.state.lock().writers = 0;
    pair.in_pipe
        .update_readiness_locked(&pair.in_pipe.state.lock());
    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, 0),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[test]
fn tee_in_memory_full_destination_backpressure() {
    let pair = TestPipePair::new(65536, 65536);
    pair.fill_in(&[0xaa; 1024]);
    pair.fill_out(65536);
    let out_poll_fd = pair.out_pipe.write_poll_fd().expect("poll fd").raw();
    let nb_flags = carrick_abi::LinuxSpliceFlags::NONBLOCK.bits();

    assert_eq!(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, nb_flags),
        DispatchOutcome::errno(LINUX_EAGAIN)
    );
    assert_wait_on(
        pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, 0),
        out_poll_fd,
        libc::POLLIN,
    );

    // O_NONBLOCK on destination writer
    let nb_pair = TestPipePair::with_flags(65536, 0, 65536, LINUX_O_NONBLOCK);
    nb_pair.fill_in(&[0xaa; 1024]);
    nb_pair.fill_out(65536);
    assert_eq!(
        nb_pair.dispatch_tee(nb_pair.in_read_fd, nb_pair.out_write_fd, 1024, 0),
        DispatchOutcome::errno(LINUX_EAGAIN)
    );
}

#[test]
fn tee_in_memory_destination_reader_closed_epipe_and_sigpipe() {
    let pair = TestPipePair::new(65536, 65536);
    // Destination readers = 0 wins even when source is empty (precedence)
    pair.out_pipe.state.lock().readers = 0;
    pair.out_pipe
        .update_readiness_locked(&pair.out_pipe.state.lock());

    let ctx = pair.dispatcher.capture_one_task_context().unwrap();
    let outcome = pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, 0);
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EPIPE));
    assert!(
        ctx.thread()
            .signal_state()
            .pending()
            .contains(carrick_abi::LINUX_SIGPIPE),
        "EPIPE must raise pending SIGPIPE"
    );

    // When SIGPIPE is ignored (SIG_IGN), EPIPE is still returned but no signal is queued
    let mut ign = LinuxSigaction::empty();
    ign.sa_handler = carrick_abi::LINUX_SIG_IGN;
    let sigpipe =
        crate::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGPIPE).unwrap();
    ctx.shared().sighand().install_action(sigpipe, ign);
    ctx.thread()
        .update_signal_state(|s| s.replace_pending_entries(&[]));

    let outcome_ign = pair.dispatch_tee(pair.in_read_fd, pair.out_write_fd, 1024, 0);
    assert_eq!(outcome_ign, DispatchOutcome::errno(LINUX_EPIPE));
    assert!(
        !ctx.thread()
            .signal_state()
            .pending()
            .contains(carrick_abi::LINUX_SIGPIPE),
        "SIG_IGN must suppress queuing SIGPIPE"
    );
}

#[test]
fn pipe_end_direction_matrix_and_fd_lifecycle_closure() {
    let pair = TestPipePair::new(65536, 65536);
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x10000]);
    let reporter = CompatReporter::default();
    let ctx = pair.dispatcher.capture_one_task_context().unwrap();

    const BUF_ADDR: u64 = 0x2000;
    const IOV_ADDR: u64 = 0x3000;
    let iov = LinuxIovec {
        iov_base: BUF_ADDR,
        iov_len: 16,
    };
    write_kernel_struct_raw(&mut memory, IOV_ADDR, &iov).expect("write iov");
    memory
        .write_bytes(BUF_ADDR, b"0123456789abcdef")
        .expect("write buf");

    let dispatch_call =
        |dispatcher: &SyscallDispatcher, nr: u64, args: [u64; 6], mem: &mut LinearMemory| {
            dispatcher
                .dispatch_normalized(
                    &ctx,
                    SyscallRequest::new(nr, SyscallArgs::from(args)),
                    mem,
                    &reporter,
                    None,
                )
                .expect("claimed")
                .expect("outcome")
        };

    // 1. Read-family operations on PipeWriter return EBADF
    let w_fd = pair.in_write_fd as u64;
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            63,
            [w_fd, BUF_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_EBADF),
        "read on pipe write end must return EBADF"
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            65,
            [w_fd, IOV_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_EBADF),
        "readv on pipe write end must return EBADF"
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            67,
            [w_fd, BUF_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE),
        "pread64 on pipe write end must return ESPIPE"
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            69,
            [w_fd, IOV_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE),
        "preadv on pipe write end must return ESPIPE"
    );

    // 2. Write-family operations on PipeReader:
    // non-positional write/writev return EBADF; positional pwrite64/pwritev return ESPIPE
    let r_fd = pair.in_read_fd as u64;
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            64,
            [r_fd, BUF_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_EBADF),
        "write on pipe read end must return EBADF"
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            66,
            [r_fd, IOV_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_EBADF),
        "writev on pipe read end must return EBADF"
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            68,
            [r_fd, BUF_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE),
        "pwrite64 on pipe read end must return ESPIPE"
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            70,
            [r_fd, IOV_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE),
        "pwritev on pipe read end must return ESPIPE"
    );

    // 3. Correct directions succeed
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            64,
            [w_fd, BUF_ADDR, 5, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            63,
            [r_fd, BUF_ADDR, 5, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::Returned { value: 5 }
    );

    // 4. Dup preserves direction and descriptor identity
    let dup_read = dispatch_call(&pair.dispatcher, 23, [r_fd, 0, 0, 0, 0, 0], &mut memory);
    let dup_read_fd = match dup_read {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("expected dup read fd, got {other:?}"),
    };
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            64,
            [dup_read_fd, BUF_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_EBADF),
        "write on duplicated read end must return EBADF"
    );

    let dup_write = dispatch_call(&pair.dispatcher, 23, [w_fd, 0, 0, 0, 0, 0], &mut memory);
    let dup_write_fd = match dup_write {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("expected dup write fd, got {other:?}"),
    };
    assert_eq!(
        dispatch_call(
            &pair.dispatcher,
            63,
            [dup_write_fd, BUF_ADDR, 1, 0, 0, 0],
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_EBADF),
        "read on duplicated write end must return EBADF"
    );

    // 5. Bidirectional HostPipe (e.g. O_RDWR FIFO or pty) permits both directions
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);
    unsafe { libc::close(host_fds[1]) };
    let pty_desc = OpenDescription::HostPipe {
        base: OpenDescriptionBase::new(carrick_abi::LINUX_O_RDWR),
        host_fd: HostFdRef::new(host_fds[0]),
        is_read_end: false,
        pipe_id: 9999,
        pty: None,
        bidirectional: true,
        write_kind: HostWriteKind::PipeLike,
        stdio_stream: None,
    };
    let bi_fd = pair
        .dispatcher
        .install_fd_at_or_above(
            3,
            OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(pty_desc)),
                LINUX_O_RDWR,
                0,
            ),
        )
        .expect("install bidirectional pipe");
    let bi_file = pair.dispatcher.open_file(bi_fd).expect("open file");
    assert!(matches!(
        bi_file.description.read().as_deref(),
        Some(OpenDescription::HostPipe {
            bidirectional: true,
            ..
        })
    ));
}

#[test]
fn dispatch_threaded_pipe_reader_write_shared_ebadf_not_enosys() {
    let pair = TestPipePair::new(65536, 65536);
    let context = pair
        .dispatcher
        .capture_one_task_context()
        .expect("task context");
    let reporter = CompatReporter::default();
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(2300));
    let futex = crate::thread::FutexTable::new();
    let mut memory = LinearMemory::new(0x4000, vec![0u8; 0x1000]);

    const PAYLOAD_ADDR: u64 = 0x4100;
    const PAYLOAD: &[u8] = b"test payload";
    memory.write_bytes(PAYLOAD_ADDR, PAYLOAD).unwrap();

    // 1. write on PipeReader must be admitted to the shared path (via write_shared_supported)
    //    and return EBADF directly, rather than falling through to unhandled syscall (ENOSYS).
    let write_reader_outcome = pair
        .dispatcher
        .dispatch_threaded(
            &context,
            SyscallRequest::new(
                64, // SYS_WRITE
                SyscallArgs::from([
                    pair.in_read_fd as u64,
                    PAYLOAD_ADDR,
                    PAYLOAD.len() as u64,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            registry.main_tid(),
            &registry,
            &futex,
        )
        .expect("dispatch_threaded write on pipe read end");

    assert_eq!(
        write_reader_outcome,
        DispatchOutcome::errno(LINUX_EBADF),
        "write on pipe reader in dispatch_threaded must return EBADF"
    );

    // 2. read on PipeWriter via dispatch_threaded returns EBADF
    let read_writer_outcome = pair
        .dispatcher
        .dispatch_threaded(
            &context,
            SyscallRequest::new(
                63, // SYS_READ
                SyscallArgs::from([
                    pair.in_write_fd as u64,
                    PAYLOAD_ADDR,
                    PAYLOAD.len() as u64,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            registry.main_tid(),
            &registry,
            &futex,
        )
        .expect("dispatch_threaded read on pipe write end");

    assert_eq!(
        read_writer_outcome,
        DispatchOutcome::errno(LINUX_EBADF),
        "read on pipe writer in dispatch_threaded must return EBADF"
    );

    // 3. Normal write on PipeWriter and read on PipeReader succeed
    let write_writer_outcome = pair
        .dispatcher
        .dispatch_threaded(
            &context,
            SyscallRequest::new(
                64, // SYS_WRITE
                SyscallArgs::from([
                    pair.in_write_fd as u64,
                    PAYLOAD_ADDR,
                    PAYLOAD.len() as u64,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            registry.main_tid(),
            &registry,
            &futex,
        )
        .expect("dispatch_threaded write on pipe write end");

    assert_eq!(
        write_writer_outcome,
        DispatchOutcome::returned_len_or_errno(PAYLOAD.len())
    );

    let read_reader_outcome = pair
        .dispatcher
        .dispatch_threaded(
            &context,
            SyscallRequest::new(
                63, // SYS_READ
                SyscallArgs::from([
                    pair.in_read_fd as u64,
                    PAYLOAD_ADDR,
                    PAYLOAD.len() as u64,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut memory,
            &reporter,
            registry.main_tid(),
            &registry,
            &futex,
        )
        .expect("dispatch_threaded read on pipe read end");

    assert_eq!(
        read_reader_outcome,
        DispatchOutcome::returned_len_or_errno(PAYLOAD.len())
    );

    let report = reporter.finish();
    assert!(
        report.unhandled_syscalls.is_empty(),
        "dispatch_threaded pipe read/write must not generate unhandled syscall events: {:?}",
        report.unhandled_syscalls
    );
}

#[test]
fn non_pipe_access_mode_readv_writev_and_splice_precedence() {
    let mut pair = TestPipePair::new(65536, 65536);
    let ctx = pair
        .dispatcher
        .capture_one_task_context()
        .expect("task context");
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x10000]);

    const BUF_ADDR: u64 = 0x2000;
    const IOV_ADDR: u64 = 0x3000;
    let iov = LinuxIovec {
        iov_base: BUF_ADDR,
        iov_len: 8,
    };
    write_kernel_struct_raw(&mut memory, IOV_ADDR, &iov).expect("write iov");
    memory
        .write_bytes(BUF_ADDR, b"01234567")
        .expect("write buf");

    // 1. In-memory SyntheticFile opened O_WRONLY: readv returns EBADF
    let wr_file_desc = OpenDescription::SyntheticFile {
        base: OpenDescriptionBase::new(carrick_abi::LINUX_O_WRONLY),
        path: "/tmp/test-wronly".to_string(),
        contents: vec![1, 2, 3, 4],
        offset: 0,
    };
    let wr_fd = pair
        .dispatcher
        .install_fd_at_or_above(
            3,
            OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(wr_file_desc)),
                carrick_abi::LINUX_O_WRONLY,
                0,
            ),
        )
        .expect("install wronly file");

    assert_eq!(
        pair.dispatcher
            .dispatch(
                &ctx,
                SyscallRequest::new(65, SyscallArgs::from([wr_fd as u64, IOV_ADDR, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(LINUX_EBADF),
        "readv on O_WRONLY in-memory file must return EBADF"
    );

    // 2. splice_source_not_readable returns true on O_WRONLY file and yields EBADF on splice(76)
    assert!(pair.dispatcher.splice_source_not_readable(wr_fd));
    assert_eq!(
        pair.dispatcher
            .dispatch(
                &ctx,
                SyscallRequest::new(
                    76, // SYS_SPLICE
                    SyscallArgs::from([wr_fd as u64, 0, pair.in_write_fd as u64, 0, 4, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(LINUX_EBADF),
        "splice with O_WRONLY source must return EBADF"
    );

    // 3. Directory description: writev returns EBADF (restoring base behavior)
    let dir_desc = OpenDescription::Directory {
        base: OpenDescriptionBase::new(carrick_abi::LINUX_O_RDONLY),
        path: "/tmp/dir".to_string(),
        metadata: RootFsMetadata {
            path: std::path::PathBuf::from("/tmp/dir"),
            kind: crate::rootfs::RootFsEntryKind::Directory,
            mode: 0o755,
            size: 0,
        },
        listing: DirListing::Pending,
        offset: 0,
        trusted_host_dir: None,
    };
    let dir_fd = pair
        .dispatcher
        .install_fd_at_or_above(
            3,
            OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(dir_desc)),
                LINUX_O_RDONLY,
                0,
            ),
        )
        .expect("install directory fd");

    assert_eq!(
        pair.dispatcher
            .dispatch(
                &ctx,
                SyscallRequest::new(66, SyscallArgs::from([dir_fd as u64, IOV_ADDR, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::errno(LINUX_EBADF),
        "writev on directory descriptor must return EBADF"
    );
}

#[test]
fn cross_mount_rename_and_link_boundary_semantics() {
    use crate::vfs::{EntryKind, Metadata, Vfs, VfsError};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestMountVfs {
        name: &'static str,
        renamed: Arc<AtomicBool>,
        linked: Arc<AtomicBool>,
    }

    impl Vfs for TestMountVfs {
        fn name(&self) -> &'static str {
            self.name
        }

        fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
            if path.contains("file.txt") {
                Ok(Metadata {
                    kind: EntryKind::File,
                    mode: 0o644,
                    size: 10,
                    uid: 0,
                    gid: 0,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                })
            } else {
                Err(LINUX_ENOENT)
            }
        }

        fn rename(&self, _from: &str, _to: &str) -> Result<(), LinuxErrno> {
            self.renamed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn link(&self, _src: &str, _dst: &str) -> Result<(), LinuxErrno> {
            self.linked.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let backend = crate::fs_backend::MemoryBackend::new();
    backend
        .set_file_contents("/rootfs_file.txt", b"payload".to_vec())
        .unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));

    let mount1_renamed = Arc::new(AtomicBool::new(false));
    let mount1_linked = Arc::new(AtomicBool::new(false));
    dispatcher.register_mount(
        "/data1",
        Box::new(TestMountVfs {
            name: "mount1",
            renamed: Arc::clone(&mount1_renamed),
            linked: Arc::clone(&mount1_linked),
        }),
    );

    let mount2_renamed = Arc::new(AtomicBool::new(false));
    let mount2_linked = Arc::new(AtomicBool::new(false));
    dispatcher.register_mount(
        "/data2",
        Box::new(TestMountVfs {
            name: "mount2",
            renamed: Arc::clone(&mount2_renamed),
            linked: Arc::clone(&mount2_linked),
        }),
    );

    let ctx = dispatcher.capture_one_task_context().unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);

    memory.write_bytes(0x4000, b"/data1/file.txt\0").unwrap();
    memory.write_bytes(0x4040, b"/rootfs_file.txt\0").unwrap();
    memory.write_bytes(0x4080, b"/data2/file.txt\0").unwrap();
    memory.write_bytes(0x40c0, b"/data1/renamed.txt\0").unwrap();
    memory.write_bytes(0x4100, b"/data1/linked.txt\0").unwrap();
    memory.write_bytes(0x4140, b"/rootfs_link.txt\0").unwrap();
    memory
        .write_bytes(0x4180, b"/data1/cross_link.txt\0")
        .unwrap();
    memory
        .write_bytes(0x41c0, b"/data2/cross_link.txt\0")
        .unwrap();

    // 1. Rename mount1 -> rootfs: EXDEV
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                38, // SYS_RENAMEAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4040, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));

    // 2. Rename rootfs -> mount1: EXDEV
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                38, // SYS_RENAMEAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4040, LINUX_AT_FDCWD, 0x4000, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));

    // 3. Rename mount1 -> mount2: EXDEV
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                38, // SYS_RENAMEAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4080, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));

    // 4. Rename within mount1 (mount1 -> mount1): Success (0)
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                38, // SYS_RENAMEAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x40c0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::Returned { value: 0 });
    assert!(mount1_renamed.load(Ordering::SeqCst));

    // 5. Link mount1 -> rootfs: EXDEV
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                37, // SYS_LINKAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4140, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));

    // 6. Link rootfs -> mount1: EXDEV
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                37, // SYS_LINKAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4040, LINUX_AT_FDCWD, 0x4180, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));

    // 7. Link mount1 -> mount2: EXDEV
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                37, // SYS_LINKAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x41c0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::errno(crate::linux_abi::LINUX_EXDEV));

    // 8. Link within mount1 (mount1 -> mount1): Success (0)
    let res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                37, // SYS_LINKAT
                SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x4100, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(res, DispatchOutcome::Returned { value: 0 });
    assert!(mount1_linked.load(Ordering::SeqCst));
}

#[test]
fn fcntl_pipe_set_capacity_routes_through_canonical_authority() {
    let mut rig = SpliceTestRig::new(0x10000);
    rig.dispatcher
        .activate_file_authority(rig.dispatcher.captured_file_table())
        .expect("activate authority");
    let (read_fd, write_fd) = rig.pipe2(0x4200);

    // Initial capacity is default (65536)
    let get_res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [read_fd, LINUX_F_GETPIPE_SZ, 0, 0, 0, 0],
    );
    assert_eq!(get_res, DispatchOutcome::Returned { value: 65536 });

    // Resize to 131072
    let set_res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [read_fd, LINUX_F_SETPIPE_SZ, 131072, 0, 0, 0],
    );
    assert_eq!(set_res, DispatchOutcome::Returned { value: 131072 });

    // Both reader and writer ends reflect the new capacity
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_FCNTL,
            [read_fd, LINUX_F_GETPIPE_SZ, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 131072 }
    );
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_FCNTL,
            [write_fd, LINUX_F_GETPIPE_SZ, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 131072 }
    );
}

#[test]
fn fcntl_pipe_set_capacity_semantic_errors() {
    let mut rig = SpliceTestRig::new(0x10000);
    rig.dispatcher
        .activate_file_authority(rig.dispatcher.captured_file_table())
        .expect("activate authority");
    let (read_fd, write_fd) = rig.pipe2(0x4200);

    // Valid pipe: request > i32::MAX returns EINVAL
    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [read_fd, LINUX_F_SETPIPE_SZ, (i32::MAX as u64) + 1, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EINVAL));

    // Valid pipe: request > 1 MiB returns EPERM
    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [read_fd, LINUX_F_SETPIPE_SZ, 1024 * 1024 + 4096, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EPERM));

    // Valid pipe: write data to pipe then try to shrink below queued bytes -> EBUSY
    rig.memory.write_bytes(0x5000, &[0x42; 8192]).unwrap();
    let write_res = rig.run(SpliceTestRig::SYS_WRITE, [write_fd, 0x5000, 8192, 0, 0, 0]);
    assert_eq!(write_res, DispatchOutcome::Returned { value: 8192 });

    // Shrinking to 4096 (< 8192 queued) returns EBUSY
    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [read_fd, LINUX_F_SETPIPE_SZ, 4096, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBUSY));

    // Invalid / closed fd returns EBADF regardless of size argument (Linux error precedence)
    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [99, LINUX_F_SETPIPE_SZ, 65536, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBADF));

    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [99, LINUX_F_SETPIPE_SZ, (i32::MAX as u64) + 1, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBADF));

    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [99, LINUX_F_SETPIPE_SZ, 1024 * 1024 + 4096, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBADF));

    // Non-pipe open fd (regular /proc file) returns EBADF regardless of size argument
    let file_fd = rig.open(0x6000, b"/proc/version\0", LINUX_O_RDONLY);
    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [file_fd, LINUX_F_SETPIPE_SZ, 65536, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBADF));

    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [file_fd, LINUX_F_SETPIPE_SZ, (i32::MAX as u64) + 1, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBADF));

    let res = rig.run(
        SpliceTestRig::SYS_FCNTL,
        [file_fd, LINUX_F_SETPIPE_SZ, 1024 * 1024 + 4096, 0, 0, 0],
    );
    assert_eq!(res, DispatchOutcome::errno(LINUX_EBADF));
}

#[test]
fn fcntl_pipe_set_capacity_preserves_authority_fatal_without_direct_fallback() {
    let mut rig = SpliceTestRig::new(0x10000);
    // Deliberately do NOT activate FileAuthority on the dispatcher
    let (read_fd, _write_fd) = rig.pipe2(0x4200);

    let ctx = rig.dispatcher.capture_one_task_context().unwrap();
    let res = rig.dispatcher.dispatch(
        &ctx,
        SyscallRequest::new(
            SpliceTestRig::SYS_FCNTL,
            SyscallArgs::from([read_fd, LINUX_F_SETPIPE_SZ, 131072, 0, 0, 0]),
        ),
        &mut rig.memory,
        &rig.reporter,
    );

    // Authority is unavailable -> fatal error, NOT lowered to errno, and no direct mutation
    assert!(matches!(
        res,
        Err(DispatchError::FileAuthorityFatal(
            crate::file_authority::AuthorityFatal::TransportUnavailable
        ))
    ));
}

#[test]
fn fcntl_pipe_host_pipe_accounting_and_set_capacity() {
    let mut host_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(host_fds.as_mut_ptr()) }, 0);

    let mut dispatcher = SyscallDispatcher::new();
    let root_table = dispatcher.captured_file_table();
    dispatcher
        .activate_file_authority(Arc::clone(&root_table))
        .expect("activate authority");

    let read_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[0]),
            is_read_end: true,
            pipe_id: 1042,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_RDONLY,
        0,
    );
    let write_open = OpenFile::from_open_description_with_status_flags(
        Arc::new(RwLock::new(OpenDescription::HostPipe {
            host_fd: HostFdRef::new(host_fds[1]),
            is_read_end: false,
            pipe_id: 1042,
            base: OpenDescriptionBase::new(0),
            pty: None,
            bidirectional: false,
            write_kind: HostWriteKind::PipeLike,
            stdio_stream: None,
        })),
        LINUX_O_WRONLY,
        0,
    );
    let (read_fd, _write_fd) = dispatcher
        .install_fd_pair_at_or_above(3, read_open, write_open)
        .expect("install host pipe pair");

    let mut memory = LinearMemory::new(0x10000, vec![0u8; 0x1000]);
    let reporter = CompatReporter::default();
    let ctx = dispatcher.capture_one_task_context().unwrap();

    let resize_res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                25,
                SyscallArgs::from([read_fd as u64, LINUX_F_SETPIPE_SZ, 131072, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("fcntl dispatch");
    assert_eq!(resize_res, DispatchOutcome::Returned { value: 131072 });

    let get_res = dispatcher
        .dispatch(
            &ctx,
            SyscallRequest::new(
                25,
                SyscallArgs::from([read_fd as u64, LINUX_F_GETPIPE_SZ, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .expect("fcntl get");
    assert_eq!(get_res, DispatchOutcome::Returned { value: 131072 });
}

/// `select(2)` on an in-memory pipe must count BOTH ends: after one byte is
/// written the read end is readable and the write end still writable, so
/// `select(r in readfds, w in writefds)` returns 2 (LTP `select01` "system
/// pipe"). The write end's host poll target is the pipe's readiness pipe,
/// whose READ end is what becomes readable when the guest side is writable;
/// polling that host fd for `POLLOUT` never fires and dropped the count to 1.
#[test]
fn pselect6_counts_in_memory_pipe_write_end_writable() {
    const SYS_PSELECT6: u64 = 72;
    let mut rig = SpliceTestRig::new(0x10000);
    let (read_fd, write_fd) = rig.pipe2(0x4200);
    rig.memory.write_bytes(0x5000, b"x").unwrap();
    assert_eq!(
        rig.run(SpliceTestRig::SYS_WRITE, [write_fd, 0x5000, 1, 0, 0, 0]),
        DispatchOutcome::Returned { value: 1 },
    );

    let readfds_addr = 0x6000u64;
    let writefds_addr = 0x6100u64;
    let timeout_addr = 0x6200u64;
    let mut set = [0u8; 128];
    set[(read_fd / 8) as usize] |= 1 << (read_fd % 8);
    rig.memory.write_bytes(readfds_addr, &set).unwrap();
    let mut set = [0u8; 128];
    set[(write_fd / 8) as usize] |= 1 << (write_fd % 8);
    rig.memory.write_bytes(writefds_addr, &set).unwrap();
    // struct timespec { 0, 100 ms }: the same non-zero budget select01 uses,
    // so a wrong answer cannot hide behind the timeout-0 short circuit.
    let mut ts = [0u8; 16];
    ts[8..16].copy_from_slice(&100_000_000i64.to_ne_bytes());
    rig.memory.write_bytes(timeout_addr, &ts).unwrap();

    let nfds = read_fd.max(write_fd) + 1;
    assert_eq!(
        rig.run(
            SYS_PSELECT6,
            [nfds, readfds_addr, writefds_addr, 0, timeout_addr, 0]
        ),
        DispatchOutcome::Returned { value: 2 },
    );
    let readfds = rig.memory.read_bytes(readfds_addr, 128).unwrap();
    assert_ne!(
        readfds[(read_fd / 8) as usize] & (1 << (read_fd % 8)),
        0,
        "read end must be reported readable"
    );
    let writefds = rig.memory.read_bytes(writefds_addr, 128).unwrap();
    assert_ne!(
        writefds[(write_fd / 8) as usize] & (1 << (write_fd % 8)),
        0,
        "write end must be reported writable"
    );
}

/// A blocking `select` on a FULL in-memory pipe's write end must park on the
/// pipe's readiness fd with the event that fd actually delivers (`POLLIN` on
/// the readiness pipe's read end), exactly as `ppoll` does. Parking with the
/// guest's `POLLOUT` on that read end never wakes, so the guest slept out its
/// whole timeout after the reader drained the pipe.
#[test]
fn pselect6_parks_full_pipe_write_end_on_readiness_pipe_pollin() {
    const SYS_PSELECT6: u64 = 72;
    let mut rig = SpliceTestRig::new(0x20000);
    let (_read_fd, write_fd) = rig.pipe2(0x4200);
    let room = rig
        .dispatcher
        .splice_pipe_write_room(write_fd as i32)
        .expect("in-memory pipe reports room");
    rig.memory.write_bytes(0x8000, &vec![0xa5u8; room]).unwrap();
    assert_eq!(
        rig.run(
            SpliceTestRig::SYS_WRITE,
            [write_fd, 0x8000, room as u64, 0, 0, 0]
        ),
        DispatchOutcome::returned_len_or_errno(room),
    );
    let write_poll_fd = match &*rig
        .dispatcher
        .open_file(write_fd as i32)
        .expect("write file")
        .description
        .read()
        .expect("open description")
    {
        OpenDescription::PipeWriter { pipe, .. } => pipe
            .write_poll_fd()
            .expect("pipe must have write poll fd")
            .raw(),
        other => panic!("unexpected open description: {other:?}"),
    };

    let writefds_addr = 0x6100u64;
    let timeout_addr = 0x6200u64;
    let mut set = [0u8; 128];
    set[(write_fd / 8) as usize] |= 1 << (write_fd % 8);
    rig.memory.write_bytes(writefds_addr, &set).unwrap();
    let mut ts = [0u8; 16];
    ts[0..8].copy_from_slice(&5i64.to_ne_bytes());
    rig.memory.write_bytes(timeout_addr, &ts).unwrap();

    let outcome = rig.run(
        SYS_PSELECT6,
        [write_fd + 1, 0, writefds_addr, 0, timeout_addr, 0],
    );
    let DispatchOutcome::WaitOnFds {
        fds,
        completion: FdWaitCompletion::Select { .. },
        ..
    } = outcome
    else {
        panic!("expected select on a full pipe to park, got {outcome:?}");
    };
    assert_eq!(
        fds.first(),
        Some((write_poll_fd, libc::POLLIN)),
        "must park on the readiness pipe with the event it delivers"
    );
}

/// LTP creat05's cleanup probe: `openat(dirfd, name, O_DIRECTORY|O_NOFOLLOW)`
/// per file, expecting ENOTDIR. Under a trusted dir the host's own
/// O_DIRECTORY|O_NOFOLLOW refusal answers that exactly — Linux reports
/// ENOTDIR for a regular file, a FIFO, AND a symlink (to a file or to a
/// directory) under that flag pair (Docker oracle, 2026-09-02) — so the lane
/// must serve it instead of falling back to a ~10-host-call resolving walk.
/// Without guest O_NOFOLLOW a symlink child must still fall back (followed).
#[cfg(target_os = "macos")]
#[test]
fn trusted_dirfd_lane_serves_nofollow_directory_probe_enotdir() {
    let (_scratch, mut dispatcher) = trusted_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);
    let root = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/walk",
        LINUX_O_DIRECTORY,
    );
    assert!(lane_dir_is_trusted(&dispatcher, root));
    let nofollow_dir = LINUX_O_RDONLY | LINUX_O_DIRECTORY | LinuxOpenFlags::NOFOLLOW.bits();
    for name in ["file.txt", "link", "fifo"] {
        let outcome = dispatcher.try_trusted_dirfd_openat(root as u64, name, nofollow_dir);
        assert!(
            matches!(outcome, Some(DispatchOutcome::Errno { errno }) if errno == LINUX_ENOTDIR),
            "{name}: O_DIRECTORY|O_NOFOLLOW must be lane-served ENOTDIR, got {outcome:?}"
        );
    }
    // A directory child is still served as a trusted directory.
    let sub = lane_openat(
        &mut dispatcher,
        &mut memory,
        root as u64,
        "sub",
        nofollow_dir,
    );
    assert!(sub >= 0 && lane_dir_is_trusted(&dispatcher, sub));
    // Without guest O_NOFOLLOW the symlink child must be FOLLOWED by the
    // slow path, never refused by the lane's probe.
    assert!(
        dispatcher
            .try_trusted_dirfd_openat(root as u64, "link", LINUX_O_RDONLY | LINUX_O_DIRECTORY)
            .is_none()
    );
}

#[test]
fn memfd_proc_self_fd_reopen_access_mode_and_seals() {
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let reporter = CompatReporter::default();
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            &d.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    #[cfg(target_arch = "aarch64")]
    const SYS_MEMFD_CREATE: u64 = 279;
    #[cfg(target_arch = "x86_64")]
    const SYS_MEMFD_CREATE: u64 = 319;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_MEMFD_CREATE: u64 = 279;

    memory.write_bytes(0x4000, b"test_memfd\0").unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_MEMFD_CREATE,
        [0x4000, 2, 0, 0, 0, 0],
    );
    let orig_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("memfd_create failed: {other:?}"),
    };
    assert!(orig_fd >= 0);

    const F_ADD_SEALS: u64 = 1033;
    const F_GET_SEALS: u64 = 1034;
    const F_SEAL_GROW: u64 = 4;
    const F_SEAL_WRITE: u64 = 8;
    const SYS_FCNTL: u64 = 25;

    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_FCNTL,
        [orig_fd as u64, F_ADD_SEALS, F_SEAL_GROW, 0, 0, 0],
    );
    assert!(matches!(outcome, DispatchOutcome::Returned { value: 0 }));

    const SYS_OPENAT: u64 = 56;
    let ro_path = format!("/proc/self/fd/{orig_fd}\0");
    memory.write_bytes(0x4100, ro_path.as_bytes()).unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [(-100_i64) as u64, 0x4100, LINUX_O_RDONLY, 0, 0, 0],
    );
    let ro_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat O_RDONLY failed: {other:?}"),
    };
    assert!(ro_fd >= 0);
    assert_ne!(ro_fd, orig_fd);

    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_FCNTL,
        [ro_fd as u64, F_GET_SEALS, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::returned_u64_or_errno(F_SEAL_GROW));

    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_FCNTL,
        [ro_fd as u64, F_ADD_SEALS, F_SEAL_WRITE, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EPERM));

    const SYS_WRITE: u64 = 64;
    memory.write_bytes(0x4200, b"data").unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_WRITE,
        [ro_fd as u64, 0x4200, 4, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EBADF));

    let rw_path = format!("/proc/self/fd/{ro_fd}\0");
    memory.write_bytes(0x4300, rw_path.as_bytes()).unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [(-100_i64) as u64, 0x4300, LINUX_O_RDWR, 0, 0, 0],
    );
    let rw_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat O_RDWR failed: {other:?}"),
    };
    assert!(rw_fd >= 0);

    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_FCNTL,
        [rw_fd as u64, F_ADD_SEALS, F_SEAL_WRITE, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_FCNTL,
        [ro_fd as u64, F_GET_SEALS, 0, 0, 0, 0],
    );
    assert_eq!(
        outcome,
        DispatchOutcome::returned_u64_or_errno(F_SEAL_GROW | F_SEAL_WRITE)
    );
}

#[test]
fn memfd_proc_self_fd_reopen_trunc_shares_inode() {
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0xab; 0x10000]);
    let reporter = CompatReporter::default();
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            &d.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    #[cfg(target_arch = "aarch64")]
    const SYS_MEMFD_CREATE: u64 = 279;
    #[cfg(target_arch = "x86_64")]
    const SYS_MEMFD_CREATE: u64 = 319;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_MEMFD_CREATE: u64 = 279;

    #[cfg(target_arch = "aarch64")]
    const SYS_OPENAT: u64 = 56;
    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT: u64 = 257;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_OPENAT: u64 = 56;

    #[cfg(target_arch = "aarch64")]
    const SYS_WRITE: u64 = 64;
    #[cfg(target_arch = "x86_64")]
    const SYS_WRITE: u64 = 1;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_WRITE: u64 = 64;

    #[cfg(target_arch = "aarch64")]
    const SYS_READ: u64 = 63;
    #[cfg(target_arch = "x86_64")]
    const SYS_READ: u64 = 0;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_READ: u64 = 63;

    #[cfg(target_arch = "aarch64")]
    const SYS_LSEEK: u64 = 62;
    #[cfg(target_arch = "x86_64")]
    const SYS_LSEEK: u64 = 8;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_LSEEK: u64 = 62;

    #[cfg(target_arch = "aarch64")]
    const SYS_FSTAT: u64 = 80;
    #[cfg(target_arch = "x86_64")]
    const SYS_FSTAT: u64 = 5;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const SYS_FSTAT: u64 = 80;

    memory.write_bytes(0x4000, b"test_trunc\0").unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_MEMFD_CREATE,
        [0x4000, 0, 0, 0, 0, 0],
    );
    let orig_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("memfd_create failed: {other:?}"),
    };
    assert!(orig_fd >= 0);

    // Write 8192 bytes
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_WRITE,
        [orig_fd as u64, 0x6000, 8192, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 8192 });

    let st = dispatcher.fd_stat_record(orig_fd).expect("stat on orig_fd");
    assert_eq!(st.size, 8192);

    // Reopen through /proc/self/fd/N with O_TRUNC
    let trunc_path = format!("/proc/self/fd/{orig_fd}\0");
    memory.write_bytes(0x4100, trunc_path.as_bytes()).unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [
            (-100_i64) as u64,
            0x4100,
            LINUX_O_RDWR | LINUX_O_TRUNC,
            0o600,
            0,
            0,
        ],
    );
    let trunc_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat /proc/self/fd/N O_TRUNC failed: {other:?}"),
    };
    assert!(trunc_fd >= 0);

    // fstat on original fd must report st_size == 0
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_FSTAT,
        [orig_fd as u64, 0x5000, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    let st_size = i64::from_ne_bytes(
        memory
            .read_bytes(0x5000 + 48, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(st_size, 0, "fstat on original fd must report st_size == 0");

    let st_orig = dispatcher
        .fd_stat_record(orig_fd)
        .expect("stat on orig_fd after trunc");
    assert_eq!(
        st_orig.size, 0,
        "fd_stat_record on original fd must report size 0"
    );

    // Seek to 0 and read on original fd must return 0 bytes
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_LSEEK,
        [orig_fd as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_READ,
        [orig_fd as u64, 0x6000, 100, 0, 0, 0],
    );
    assert_eq!(
        outcome,
        DispatchOutcome::Returned { value: 0 },
        "read on original fd must return 0 bytes"
    );
}

#[test]
fn proc_self_fd_reopen_overlay_file_write_after_reopen_visible_in_reopened() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x2000]);
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            &d.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    const SYS_OPENAT: u64 = 56;
    const SYS_CLOSE: u64 = 57;
    const SYS_READ: u64 = 63;
    const SYS_WRITE: u64 = 64;

    // 1. Create a regular file through the overlay with O_RDWR.
    memory.write_bytes(0x4000, b"/test_reopen.txt\0").unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_CREAT | LINUX_O_RDWR,
            0o644,
            0,
            0,
        ],
    );
    let orig_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat create failed: {other:?}"),
    };
    assert!(orig_fd >= 0);

    // Initial write
    memory.write_bytes(0x4100, b"initial ").unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_WRITE,
        [orig_fd as u64, 0x4100, 8, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });

    // 2. Re-open read-only through /proc/self/fd/<orig_fd>.
    let ro_path = format!("/proc/self/fd/{orig_fd}\0");
    memory.write_bytes(0x4200, ro_path.as_bytes()).unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [LINUX_AT_FDCWD, 0x4200, LINUX_O_RDONLY, 0, 0, 0],
    );
    let ro_fd = match outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat /proc/self/fd failed: {other:?}"),
    };
    assert!(ro_fd >= 0);
    assert_ne!(ro_fd, orig_fd);

    // 3. Write through the original fd AFTER the read-only re-open.
    memory.write_bytes(0x4300, b"subsequent").unwrap();
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_WRITE,
        [orig_fd as u64, 0x4300, 10, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 10 });

    // 4. Read bytes back through the re-opened fd: must see the subsequent write!
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_READ,
        [ro_fd as u64, 0x4400, 18, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 18 });
    let read_bytes = memory.read_bytes(0x4400, 18).unwrap();
    assert_eq!(read_bytes, b"initial subsequent");

    // Re-opened fd is read-only, write must fail with EBADF
    let outcome = run(
        &mut dispatcher,
        &mut memory,
        SYS_WRITE,
        [ro_fd as u64, 0x4300, 10, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::errno(LINUX_EBADF));

    run(
        &mut dispatcher,
        &mut memory,
        SYS_CLOSE,
        [orig_fd as u64, 0, 0, 0, 0, 0],
    );
    run(
        &mut dispatcher,
        &mut memory,
        SYS_CLOSE,
        [ro_fd as u64, 0, 0, 0, 0, 0],
    );
}

#[test]
fn proc_self_fd_reopen_offsets_are_independent() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x2000]);
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            &d.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    const SYS_OPENAT: u64 = 56;
    const SYS_CLOSE: u64 = 57;
    const SYS_LSEEK: u64 = 62;
    const SYS_READ: u64 = 63;
    const SYS_WRITE: u64 = 64;

    // --- Part A: Regular host file ---
    memory.write_bytes(0x4000, b"/test_offsets.txt\0").unwrap();
    let orig_fd = match run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_CREAT | LINUX_O_RDWR,
            0o644,
            0,
            0,
        ],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat failed: {other:?}"),
    };

    memory.write_bytes(0x4100, b"abcdefghij").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_WRITE,
            [orig_fd as u64, 0x4100, 10, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 10 },
    );

    // Seek orig_fd back to offset 0
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_LSEEK,
            [orig_fd as u64, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 },
    );

    // Reopen through /proc/self/fd/<orig_fd>
    let ro_path = format!("/proc/self/fd/{orig_fd}\0");
    memory.write_bytes(0x4200, ro_path.as_bytes()).unwrap();
    let ro_fd = match run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [LINUX_AT_FDCWD, 0x4200, LINUX_O_RDONLY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat ro failed: {other:?}"),
    };

    // Read 3 bytes from orig_fd -> should read "abc", orig_fd offset is now 3
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [orig_fd as u64, 0x4300, 3, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 3 },
    );
    assert_eq!(memory.read_bytes(0x4300, 3).unwrap(), b"abc");

    // Read 4 bytes from ro_fd -> should read "abcd", ro_fd offset is now 4 (independent!)
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [ro_fd as u64, 0x4300, 4, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 4 },
    );
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b"abcd");

    // Read 3 more bytes from orig_fd -> should read "def", proving orig_fd was at 3
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [orig_fd as u64, 0x4300, 3, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 3 },
    );
    assert_eq!(memory.read_bytes(0x4300, 3).unwrap(), b"def");

    // Read 4 more bytes from ro_fd -> should read "efgh", proving ro_fd was at 4
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [ro_fd as u64, 0x4300, 4, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 4 },
    );
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b"efgh");

    run(
        &mut dispatcher,
        &mut memory,
        SYS_CLOSE,
        [orig_fd as u64, 0, 0, 0, 0, 0],
    );
    run(
        &mut dispatcher,
        &mut memory,
        SYS_CLOSE,
        [ro_fd as u64, 0, 0, 0, 0, 0],
    );

    // --- Part B: Anonymous O_TMPFILE host file ---
    memory.write_bytes(0x4000, b".\0").unwrap();
    let tmp_fd = match run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [
            LINUX_AT_FDCWD,
            0x4000,
            carrick_abi::LINUX_O_TMPFILE | LINUX_O_RDWR,
            0o600,
            0,
            0,
        ],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat O_TMPFILE failed: {other:?}"),
    };

    memory.write_bytes(0x4100, b"0123456789").unwrap();
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_WRITE,
            [tmp_fd as u64, 0x4100, 10, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 10 },
    );

    // Seek tmp_fd back to 0
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_LSEEK,
            [tmp_fd as u64, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 },
    );

    // Reopen through /proc/self/fd/<tmp_fd>
    let ro_tmp_path = format!("/proc/self/fd/{tmp_fd}\0");
    memory.write_bytes(0x4200, ro_tmp_path.as_bytes()).unwrap();
    let ro_tmp_fd = match run(
        &mut dispatcher,
        &mut memory,
        SYS_OPENAT,
        [LINUX_AT_FDCWD, 0x4200, LINUX_O_RDONLY, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("openat ro tmpfile failed: {other:?}"),
    };

    // Read 3 bytes from tmp_fd -> should read "012", tmp_fd offset is now 3
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [tmp_fd as u64, 0x4300, 3, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 3 },
    );
    assert_eq!(memory.read_bytes(0x4300, 3).unwrap(), b"012");

    // Read 4 bytes from ro_tmp_fd -> should read "0123", ro_tmp_fd offset is now 4 (independent!)
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [ro_tmp_fd as u64, 0x4300, 4, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 4 },
    );
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b"0123");

    // Read 3 more bytes from tmp_fd -> should read "345", proving tmp_fd offset was at 3
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [tmp_fd as u64, 0x4300, 3, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 3 },
    );
    assert_eq!(memory.read_bytes(0x4300, 3).unwrap(), b"345");

    // Read 4 more bytes from ro_tmp_fd -> should read "4567", proving ro_tmp_fd offset was at 4
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            SYS_READ,
            [ro_tmp_fd as u64, 0x4300, 4, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 4 },
    );
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b"4567");

    run(
        &mut dispatcher,
        &mut memory,
        SYS_CLOSE,
        [tmp_fd as u64, 0, 0, 0, 0, 0],
    );
    run(
        &mut dispatcher,
        &mut memory,
        SYS_CLOSE,
        [ro_tmp_fd as u64, 0, 0, 0, 0, 0],
    );
}

#[test]
fn lseek_data_and_hole_across_backends() {
    use carrick_abi::{LINUX_ENXIO, LINUX_SEEK_DATA, LINUX_SEEK_HOLE};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    let dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x1000, vec![0; 0x10000]);
    let reporter = CompatReporter::default();

    const SYS_LSEEK: u64 = 62;

    let lseek =
        |dispatcher: &SyscallDispatcher, fd: i32, off: i64, whence: u64, mem: &mut LinearMemory| {
            let ctx = dispatcher.capture_one_task_context().unwrap();
            match dispatcher
                .dispatch_normalized(
                    &ctx,
                    SyscallRequest::new(
                        SYS_LSEEK,
                        SyscallArgs::from([fd as u64, off as u64, whence, 0, 0, 0]),
                    ),
                    mem,
                    &reporter,
                    None,
                )
                .expect("claimed")
            {
                Ok(outcome) => outcome,
                Err(crate::dispatch::DispatchError::Errno(errno)) => DispatchOutcome::errno(errno),
                other => panic!("unexpected outcome: {other:?}"),
            }
        };

    // 1. Dense in-memory file (100 bytes)
    let dense_desc = OpenDescription::File {
        base: OpenDescriptionBase::new(0),
        path: "/dense_file".to_string(),
        metadata: RootFsMetadata {
            path: PathBuf::from("/dense_file"),
            kind: RootFsEntryKind::File,
            mode: 0o644,
            size: 100,
        },
        contents: FileContents::dense(vec![0xAA; 100]),
        offset: 0,
        writable: true,
    };
    let dense_fd = match dispatcher.install_fd(dense_desc, 0) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("install dense fd: {other:?}"),
    };

    // SEEK_DATA
    assert_eq!(
        lseek(&dispatcher, dense_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 50, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 50 }
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 100, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 200, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, -1, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // SEEK_HOLE
    assert_eq!(
        lseek(&dispatcher, dense_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 50, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 100, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 200, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, -1, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // Check offset was updated to 100 by the last successful SEEK_HOLE
    assert_eq!(
        lseek(&dispatcher, dense_fd, 0, LINUX_SEEK_CUR, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );

    // Invalid whence
    assert_eq!(
        lseek(&dispatcher, dense_fd, 0, 5, &mut memory),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    assert_eq!(
        lseek(&dispatcher, dense_fd, 0, u64::MAX, &mut memory),
        DispatchOutcome::errno(LINUX_EINVAL)
    );

    // 2. RootFsBacked file (100 bytes)
    let rootfs_desc = OpenDescription::File {
        base: OpenDescriptionBase::new(0),
        path: "/rootfs_file".to_string(),
        metadata: RootFsMetadata {
            path: PathBuf::from("/rootfs_file"),
            kind: RootFsEntryKind::File,
            mode: 0o644,
            size: 100,
        },
        contents: FileContents::shared_backed(Arc::from(vec![0xBB; 100]), BTreeMap::new(), 100),
        offset: 0,
        writable: true,
    };
    let rootfs_fd = match dispatcher.install_fd(rootfs_desc, 0) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("install rootfs fd: {other:?}"),
    };
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, 50, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 50 }
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, 100, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, -1, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, 50, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, 100, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, rootfs_fd, -1, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // 3. InMemoryFile (100 bytes)
    let memfile_desc = OpenDescription::InMemoryFile {
        base: OpenDescriptionBase::new(0),
        path: "/inmem_file".to_string(),
        contents: Arc::new(parking_lot::RwLock::new(crate::vfs::SparseBuffer::from(
            vec![0xCC; 100],
        ))),
        offset: 0,
        writable: true,
        max_size: 1000,
    };
    let memfile_fd = match dispatcher.install_fd(memfile_desc, 0) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("install memfile fd: {other:?}"),
    };
    assert_eq!(
        lseek(&dispatcher, memfile_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, 50, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 50 }
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, 100, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, -1, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, 50, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, 100, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, memfile_fd, -1, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // 4. SyntheticFile (100 bytes)
    let synth_desc = OpenDescription::SyntheticFile {
        base: OpenDescriptionBase::new(0),
        path: "/synth_file".to_string(),
        contents: vec![0xDD; 100],
        offset: 0,
    };
    let synth_fd = match dispatcher.install_fd(synth_desc, 0) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("install synth fd: {other:?}"),
    };
    assert_eq!(
        lseek(&dispatcher, synth_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, 50, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 50 }
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, 100, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, -1, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, 50, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, 100, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, synth_fd, -1, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // 5. HostBacked file (1 MiB sparse file: 4 KiB data at 0, hole, 4 KiB data at 512 KiB, hole to EOF)
    use std::os::fd::AsRawFd;
    let temp = tempfile::NamedTempFile::new().unwrap();
    let raw_fd = temp.as_file().as_raw_fd();
    unsafe {
        assert_eq!(libc::ftruncate(raw_fd, 1048576), 0);
        let buf = [0xEEu8; 4096];
        assert_eq!(libc::pwrite(raw_fd, buf.as_ptr().cast(), 4096, 0), 4096);
        assert_eq!(
            libc::pwrite(raw_fd, buf.as_ptr().cast(), 4096, 524288),
            4096
        );
    }
    let owned_fd: std::os::fd::OwnedFd = temp.into_file().into();
    let host_backed_desc = OpenDescription::File {
        base: OpenDescriptionBase::new(0),
        path: "/host_backed_sparse".to_string(),
        metadata: RootFsMetadata {
            path: PathBuf::from("/host_backed_sparse"),
            kind: RootFsEntryKind::File,
            mode: 0o644,
            size: 1048576,
        },
        contents: FileContents::host_backed(owned_fd),
        offset: 0,
        writable: true,
    };
    let host_backed_fd = match dispatcher.install_fd(host_backed_desc, 0) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("install host-backed fd: {other:?}"),
    };
    assert_eq!(
        lseek(&dispatcher, host_backed_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            100,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            4096,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 524288 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            524288,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 524288 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            528384,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            1048576,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            -1,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    assert_eq!(
        lseek(&dispatcher, host_backed_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 4096 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            100,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 4096 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            4096,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 4096 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            524288,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 528384 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            528384,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 528384 }
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            1048576,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            -1,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // Verify offset was tracked in OpenDescription::File
    assert_eq!(
        lseek(
            &dispatcher,
            host_backed_fd,
            4096,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::Returned { value: 524288 }
    );
    assert_eq!(
        lseek(&dispatcher, host_backed_fd, 0, LINUX_SEEK_CUR, &mut memory),
        DispatchOutcome::Returned { value: 524288 }
    );

    // 6. HostFile
    use std::os::fd::IntoRawFd;
    let temp_hf = tempfile::NamedTempFile::new().unwrap();
    let path_hf = temp_hf.path().to_path_buf();
    let raw_hf = temp_hf.into_file().into_raw_fd();
    unsafe {
        assert_eq!(libc::ftruncate(raw_hf, 1048576), 0);
        let buf = [0xFFu8; 4096];
        assert_eq!(libc::pwrite(raw_hf, buf.as_ptr().cast(), 4096, 0), 4096);
        assert_eq!(
            libc::pwrite(raw_hf, buf.as_ptr().cast(), 4096, 524288),
            4096
        );
    }
    let hf_desc = OpenDescription::HostFile {
        base: OpenDescriptionBase::new(0),
        host_fd: HostFdRef::new(raw_hf),
        metadata: RootFsMetadata {
            path: path_hf,
            kind: RootFsEntryKind::File,
            mode: 0o644,
            size: 1048576,
        },
        writable: true,
    };
    let hf_fd = match dispatcher.install_fd(hf_desc, 0) {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("install host file fd: {other:?}"),
    };
    assert_eq!(
        lseek(&dispatcher, hf_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 100, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 100 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 4096, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 524288 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 524288, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::Returned { value: 524288 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 528384, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 1048576, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, -1, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    assert_eq!(
        lseek(&dispatcher, hf_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 4096 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 100, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 4096 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 4096, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 4096 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 524288, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 528384 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 528384, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::Returned { value: 528384 }
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, 1048576, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );
    assert_eq!(
        lseek(&dispatcher, hf_fd, -1, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_ENXIO)
    );

    // 7. Directory returns EINVAL on whence 3/4
    let dir_open = test_directory_open_file("/some_dir");
    let dir_fd = match dispatcher.install_fd_at_or_above(3, dir_open) {
        Ok(fd) => fd,
        Err(e) => panic!("install dir fd: {e:?}"),
    };
    assert_eq!(
        lseek(&dispatcher, dir_fd, 0, LINUX_SEEK_DATA, &mut memory),
        DispatchOutcome::errno(LINUX_EINVAL)
    );
    assert_eq!(
        lseek(&dispatcher, dir_fd, 0, LINUX_SEEK_HOLE, &mut memory),
        DispatchOutcome::errno(LINUX_EINVAL)
    );

    // 8. Pipe returns ESPIPE on whence 3/4
    let pipe_pair = TestPipePair::new(4096, 4096);
    let pipe_read = pipe_pair.in_read_fd;
    let pipe_write = pipe_pair.in_write_fd;
    assert_eq!(
        lseek(
            &pipe_pair.dispatcher,
            pipe_read,
            0,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE)
    );
    assert_eq!(
        lseek(
            &pipe_pair.dispatcher,
            pipe_read,
            0,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE)
    );
    assert_eq!(
        lseek(
            &pipe_pair.dispatcher,
            pipe_write,
            0,
            LINUX_SEEK_DATA,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE)
    );
    assert_eq!(
        lseek(
            &pipe_pair.dispatcher,
            pipe_write,
            0,
            LINUX_SEEK_HOLE,
            &mut memory
        ),
        DispatchOutcome::errno(LINUX_ESPIPE)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_seekholemap_truncate_write_cycle() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    memory.write_bytes(0x4000, b"/test_sparse.bin\0").unwrap();
    memory.write_bytes(0x5000, b"x\0").unwrap();

    let fd = lane_syscall(
        &mut dispatcher,
        &mut memory,
        56, // openat
        [
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_CREAT | LINUX_O_RDWR | LINUX_O_TRUNC,
            0o644,
            0,
            0,
        ],
    );
    assert!(fd >= 0, "openat failed: {fd}");

    for offset in [4096u64, 8192, 16384] {
        let rc_trunc = lane_syscall(&mut dispatcher, &mut memory, 46, [fd as u64, 0, 0, 0, 0, 0]);
        assert_eq!(rc_trunc, 0, "ftruncate(0) failed");

        let rc_pwrite = lane_syscall(
            &mut dispatcher,
            &mut memory,
            68, // pwrite64
            [fd as u64, 0x5000, 1, offset, 0, 0],
        );
        assert_eq!(rc_pwrite, 1, "pwrite64 failed");

        let rc_sync = lane_syscall(&mut dispatcher, &mut memory, 82, [fd as u64, 0, 0, 0, 0, 0]);
        assert_eq!(rc_sync, 0, "fsync failed");

        let d0 = lane_syscall(
            &mut dispatcher,
            &mut memory,
            62, // lseek
            [fd as u64, 0, LINUX_SEEK_DATA as u64, 0, 0, 0],
        );
        assert_eq!(d0, offset as i64, "SEEK_DATA at 0 must find {offset}");

        let h0 = lane_syscall(
            &mut dispatcher,
            &mut memory,
            62, // lseek
            [fd as u64, 0, LINUX_SEEK_HOLE as u64, 0, 0, 0],
        );
        assert_eq!(h0, 0, "SEEK_HOLE at 0 must find 0");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn test_creat_through_guest_created_symlink_to_dir() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/realdir").unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // Guest creates symlink /symdir -> realdir
    memory.write_bytes(0x4000, b"realdir\0").unwrap();
    memory.write_bytes(0x5000, b"/symdir\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        36,
        [0x4000, LINUX_AT_FDCWD, 0x5000, 0, 0, 0],
    );
    assert_eq!(rc, 0, "symlinkat failed: {rc}");

    // Guest creates file inside /symdir/testfile.txt
    memory
        .write_bytes(0x6000, b"/symdir/testfile.txt\0")
        .unwrap();
    let fd = lane_syscall(
        &mut dispatcher,
        &mut memory,
        56, // openat
        [
            LINUX_AT_FDCWD,
            0x6000,
            LINUX_O_CREAT | LINUX_O_WRONLY,
            0o644,
            0,
            0,
        ],
    );
    assert!(fd >= 0, "creat through symlink to dir failed: {fd}");
}

#[cfg(target_os = "macos")]
#[test]
fn test_intermediate_symlink_loop_returns_eloop() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/test_eloop").unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // Guest creates test_eloop/test_eloop -> ../test_eloop
    memory.write_bytes(0x4000, b"../test_eloop\0").unwrap();
    memory
        .write_bytes(0x5000, b"/test_eloop/test_eloop\0")
        .unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            36,
            [0x4000, LINUX_AT_FDCWD, 0x5000, 0, 0, 0]
        ),
        0
    );

    // Path repeating /test_eloop 43 times
    let mut path = "/test_eloop".to_string();
    for _ in 0..42 {
        path.push_str("/test_eloop");
    }
    memory
        .write_bytes(0x6000, format!("{path}\0").as_bytes())
        .unwrap();

    // lstat on 43-hop path must return ELOOP, not 0!
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79, // newfstatat
        [
            LINUX_AT_FDCWD,
            0x6000,
            0x7000,
            LINUX_AT_SYMLINK_NOFOLLOW,
            0,
            0,
        ],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ELOOP.get()),
        "lstat on 43-hop intermediate loop should be ELOOP"
    );

    // readlink on 43-hop path must return ELOOP, not succeed!
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        78, // readlinkat
        [LINUX_AT_FDCWD, 0x6000, 0x7000, 1024, 0, 0],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ELOOP.get()),
        "readlink on 43-hop intermediate loop should be ELOOP"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_rename_symlink_into_symlinked_dir_preserves_symlink() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/realdir").unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // Create /symdir -> realdir
    memory.write_bytes(0x4000, b"realdir\0").unwrap();
    memory.write_bytes(0x5000, b"/symdir\0").unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            36,
            [0x4000, LINUX_AT_FDCWD, 0x5000, 0, 0, 0]
        ),
        0
    );

    // Create /mylink -> target_value
    memory.write_bytes(0x4000, b"target_value\0").unwrap();
    memory.write_bytes(0x5000, b"/mylink\0").unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            36,
            [0x4000, LINUX_AT_FDCWD, 0x5000, 0, 0, 0]
        ),
        0
    );

    // Rename /mylink -> /symdir/movedlink
    memory.write_bytes(0x4000, b"/mylink\0").unwrap();
    memory.write_bytes(0x5000, b"/symdir/movedlink\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        38, // renameat
        [LINUX_AT_FDCWD, 0x4000, LINUX_AT_FDCWD, 0x5000, 0, 0],
    );
    assert_eq!(rc, 0, "renameat failed: {rc}");

    // lstat /symdir/movedlink should report S_IFLNK
    memory.write_bytes(0x6000, b"/symdir/movedlink\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79, // newfstatat
        [
            LINUX_AT_FDCWD,
            0x6000,
            0x7000,
            LINUX_AT_SYMLINK_NOFOLLOW,
            0,
            0,
        ],
    );
    assert_eq!(rc, 0, "newfstatat failed: {rc}");
    let mode = u32::from_ne_bytes(
        memory
            .read_bytes(0x7000 + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        mode & 0o170000,
        0o120000,
        "moved link must still be S_IFLNK"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_rmdir_after_unlinking_files() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // Create /testdir
    memory.write_bytes(0x4000, b"/testdir\0").unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            34,
            [LINUX_AT_FDCWD, 0x4000, 0o755, 0, 0, 0]
        ),
        0
    );

    // Create /testdir/file1, /testdir/file2
    memory.write_bytes(0x4000, b"/testdir/file1\0").unwrap();
    let fd1 = lane_syscall(
        &mut dispatcher,
        &mut memory,
        56,
        [
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_CREAT | LINUX_O_WRONLY,
            0o644,
            0,
            0,
        ],
    );
    assert!(fd1 >= 0);
    lane_syscall(
        &mut dispatcher,
        &mut memory,
        57,
        [fd1 as u64, 0, 0, 0, 0, 0],
    );
    // Create /testdir/file2
    memory.write_bytes(0x4000, b"/testdir/file2\0").unwrap();
    let fd2 = lane_syscall(
        &mut dispatcher,
        &mut memory,
        56,
        [
            LINUX_AT_FDCWD,
            0x4000,
            LINUX_O_CREAT | LINUX_O_WRONLY,
            0o644,
            0,
            0,
        ],
    );
    assert!(fd2 >= 0);
    lane_syscall(
        &mut dispatcher,
        &mut memory,
        57,
        [fd2 as u64, 0, 0, 0, 0, 0],
    );

    // Stat /testdir while files exist: caches InodeRecord in dentry cache
    memory.write_bytes(0x4000, b"/testdir\0").unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            79,
            [
                LINUX_AT_FDCWD,
                0x4000,
                0x7000,
                LINUX_AT_SYMLINK_NOFOLLOW,
                0,
                0
            ]
        ),
        0
    );

    // Unlink both files
    memory.write_bytes(0x4000, b"/testdir/file1\0").unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            35,
            [LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0]
        ),
        0
    );
    memory.write_bytes(0x4000, b"/testdir/file2\0").unwrap();
    assert_eq!(
        lane_syscall(
            &mut dispatcher,
            &mut memory,
            35,
            [LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0]
        ),
        0
    );

    // Check fstatat on /testdir -> st_nlink must be 2, not stale!
    memory.write_bytes(0x4000, b"/testdir\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [
            LINUX_AT_FDCWD,
            0x4000,
            0x7000,
            LINUX_AT_SYMLINK_NOFOLLOW,
            0,
            0,
        ],
    );
    assert_eq!(rc, 0);
    let nlink = u32::from_ne_bytes(
        memory
            .read_bytes(0x7000 + 20, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(nlink, 2, "empty dir nlink must be 2");

    // rmdir /testdir via unlinkat(..., AT_REMOVEDIR)
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        35,
        [LINUX_AT_FDCWD, 0x4000, 0x200, 0, 0, 0],
    );
    assert_eq!(rc, 0, "rmdir should succeed");
}

#[cfg(target_os = "macos")]
#[test]
fn test_stat_absolute_path_after_chroot() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/jail").unwrap();
    backend
        .set_file_contents("/jail/testfile", b"hello".to_vec())
        .unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // Set chroot root to /jail
    dispatcher
        .capture_one_task_context()
        .unwrap()
        .resources()
        .fs_context()
        .set_chroot_root(Some("/jail".to_owned()));

    // stat("/testfile") - on unchanged code, dentry fast path looks up /testfile on rootfs and fails ENOENT (-2)
    memory.write_bytes(0x4000, b"/testfile\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(rc, 0, "stat(/testfile) after chroot should succeed");
}

#[cfg(target_os = "macos")]
#[test]
fn test_stat_and_lookup_dot_leaf() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/mydir").unwrap();
    backend
        .set_file_contents("/mydir/myfile", b"data".to_vec())
        .unwrap();
    backend.symlink(".", "/mydir/dotsym").unwrap();
    backend.symlink("/mydir/myfile", "/mydir/filesym").unwrap();
    backend.symlink("/mydir", "/mydir/dirsym").unwrap();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // 1. stat("/mydir/.") succeeds and reports S_IFDIR
    memory.write_bytes(0x4000, b"/mydir/.\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(rc, 0, "stat(/mydir/.) should succeed");
    let mode = u32::from_ne_bytes(
        memory
            .read_bytes(0x7000 + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mode & 0o170000, 0o040000, "must be S_IFDIR");

    // 2. stat("/mydir/myfile/.") fails with ENOTDIR (-20)
    memory.write_bytes(0x4000, b"/mydir/myfile/.\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ENOTDIR.get()),
        "stat(/mydir/myfile/.) should be ENOTDIR"
    );

    // 3. stat("/mydir/dotsym") followed resolves to . (/mydir) and reports S_IFDIR
    memory.write_bytes(0x4000, b"/mydir/dotsym\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(rc, 0, "stat(/mydir/dotsym) should succeed");
    let mode = u32::from_ne_bytes(
        memory
            .read_bytes(0x7000 + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mode & 0o170000, 0o040000, "dotsym followed must be S_IFDIR");

    // 4. stat and lstat on "/mydir/myfile/" fails with ENOTDIR
    memory.write_bytes(0x4000, b"/mydir/myfile/\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ENOTDIR.get()),
        "stat(/mydir/myfile/) should be ENOTDIR"
    );
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [
            LINUX_AT_FDCWD,
            0x4000,
            0x7000,
            crate::linux_abi::LINUX_AT_SYMLINK_NOFOLLOW,
            0,
            0,
        ],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ENOTDIR.get()),
        "lstat(/mydir/myfile/) should be ENOTDIR"
    );

    // 5. symlink to file with trailing slash: stat and lstat must be ENOTDIR
    memory.write_bytes(0x4000, b"/mydir/filesym/\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ENOTDIR.get()),
        "stat(/mydir/filesym/) should be ENOTDIR"
    );
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [
            LINUX_AT_FDCWD,
            0x4000,
            0x7000,
            crate::linux_abi::LINUX_AT_SYMLINK_NOFOLLOW,
            0,
            0,
        ],
    );
    assert_eq!(
        rc,
        -i64::from(crate::linux_abi::LINUX_ENOTDIR.get()),
        "lstat(/mydir/filesym/) should be ENOTDIR"
    );

    // 6. symlink to dir with trailing slash: lstat must follow and report S_IFDIR
    memory.write_bytes(0x4000, b"/mydir/dirsym/\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [
            LINUX_AT_FDCWD,
            0x4000,
            0x7000,
            crate::linux_abi::LINUX_AT_SYMLINK_NOFOLLOW,
            0,
            0,
        ],
    );
    assert_eq!(rc, 0, "lstat(/mydir/dirsym/) should follow and succeed");
    let mode = u32::from_ne_bytes(
        memory
            .read_bytes(0x7000 + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mode & 0o170000, 0o040000, "dirsym/ must be S_IFDIR");

    // 7. symlink to dir with /.: stat must report S_IFDIR
    memory.write_bytes(0x4000, b"/mydir/dirsym/.\0").unwrap();
    let rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        79,
        [LINUX_AT_FDCWD, 0x4000, 0x7000, 0, 0, 0],
    );
    assert_eq!(rc, 0, "stat(/mydir/dirsym/.) should succeed");
    let mode = u32::from_ne_bytes(
        memory
            .read_bytes(0x7000 + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mode & 0o170000, 0o040000, "dirsym/. must be S_IFDIR");
}

#[cfg(target_os = "macos")]
#[test]
fn test_path_resolution_observable_behavior_pinned() {
    let scratch = tempfile::tempdir().unwrap();
    let backend = crate::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap();
    backend.make_dir("/mydir").unwrap();
    backend
        .set_file_contents("/mydir/myfile", b"hello world".to_vec())
        .unwrap();
    backend.symlink("/mydir", "/mydir/dirsym").unwrap();
    backend.symlink("/mydir/myfile", "/mydir/filesym").unwrap();

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x20000]);

    // Helpers to call each of the 7 entry points:
    // 1. openat (56)
    let call_openat = |dispatcher: &mut SyscallDispatcher,
                       memory: &mut LinearMemory,
                       dirfd: u64,
                       path: &str,
                       flags: u64|
     -> i64 {
        memory
            .write_bytes(0x4000, format!("{path}\0").as_bytes())
            .unwrap();
        lane_syscall(dispatcher, memory, 56, [dirfd, 0x4000, flags, 0, 0, 0])
    };
    // 2. newfstatat (79)
    let call_newfstatat = |dispatcher: &mut SyscallDispatcher,
                           memory: &mut LinearMemory,
                           dirfd: u64,
                           path: &str,
                           flags: u64|
     -> (i64, u32) {
        memory
            .write_bytes(0x4000, format!("{path}\0").as_bytes())
            .unwrap();
        memory.write_bytes(0x7000, &[0u8; 256]).unwrap();
        let rc = lane_syscall(dispatcher, memory, 79, [dirfd, 0x4000, 0x7000, flags, 0, 0]);
        let mode = if rc == 0 {
            u32::from_ne_bytes(
                memory
                    .read_bytes(0x7000 + 16, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        } else {
            0
        };
        (rc, mode)
    };
    // 3. fstat (80)
    let call_fstat =
        |dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory, fd: i32| -> (i64, u32) {
            memory.write_bytes(0x7000, &[0u8; 256]).unwrap();
            let rc = lane_syscall(dispatcher, memory, 80, [fd as u64, 0x7000, 0, 0, 0, 0]);
            let mode = if rc == 0 {
                u32::from_ne_bytes(
                    memory
                        .read_bytes(0x7000 + 16, 4)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            } else {
                0
            };
            (rc, mode)
        };
    // 4. statx (291)
    let call_statx = |dispatcher: &mut SyscallDispatcher,
                      memory: &mut LinearMemory,
                      dirfd: u64,
                      path: &str,
                      flags: u64|
     -> (i64, u32) {
        memory
            .write_bytes(0x4000, format!("{path}\0").as_bytes())
            .unwrap();
        memory.write_bytes(0x8000, &[0u8; 256]).unwrap();
        let rc = lane_syscall(
            dispatcher,
            memory,
            291,
            [dirfd, 0x4000, flags, 0x7ff, 0x8000, 0],
        );
        let mode = if rc == 0 {
            u16::from_ne_bytes(
                memory
                    .read_bytes(0x8000 + 28, 2)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ) as u32
        } else {
            0
        };
        (rc, mode)
    };
    // 5. x86_stat
    let call_x86_stat =
        |dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory, path: &str| -> (i64, u32) {
            memory
                .write_bytes(0x4000, format!("{path}\0").as_bytes())
                .unwrap();
            memory.write_bytes(0x7000, &[0u8; 256]).unwrap();
            let rc = lane_syscall(
                dispatcher,
                memory,
                carrick_abi::CARRICK_PRIVATE_X86_STAT,
                [0x4000, 0x7000, 0, 0, 0, 0],
            );
            let mode = if rc == 0 {
                u32::from_ne_bytes(
                    memory
                        .read_bytes(0x7000 + 24, 4)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            } else {
                0
            };
            (rc, mode)
        };
    // 6. x86_lstat
    let call_x86_lstat =
        |dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory, path: &str| -> (i64, u32) {
            memory
                .write_bytes(0x4000, format!("{path}\0").as_bytes())
                .unwrap();
            memory.write_bytes(0x7000, &[0u8; 256]).unwrap();
            let rc = lane_syscall(
                dispatcher,
                memory,
                carrick_abi::CARRICK_PRIVATE_X86_LSTAT,
                [0x4000, 0x7000, 0, 0, 0, 0],
            );
            let mode = if rc == 0 {
                u32::from_ne_bytes(
                    memory
                        .read_bytes(0x7000 + 24, 4)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            } else {
                0
            };
            (rc, mode)
        };
    // 7. x86_fstat
    let call_x86_fstat =
        |dispatcher: &mut SyscallDispatcher, memory: &mut LinearMemory, fd: i32| -> (i64, u32) {
            memory.write_bytes(0x7000, &[0u8; 256]).unwrap();
            let rc = lane_syscall(
                dispatcher,
                memory,
                carrick_abi::CARRICK_PRIVATE_X86_FSTAT,
                [fd as u64, 0x7000, 0, 0, 0, 0],
            );
            let mode = if rc == 0 {
                u32::from_ne_bytes(
                    memory
                        .read_bytes(0x7000 + 24, 4)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            } else {
                0
            };
            (rc, mode)
        };
    // 8. x86_newfstatat
    let call_x86_newfstatat = |dispatcher: &mut SyscallDispatcher,
                               memory: &mut LinearMemory,
                               dirfd: u64,
                               path: &str,
                               flags: u64|
     -> (i64, u32) {
        memory
            .write_bytes(0x4000, format!("{path}\0").as_bytes())
            .unwrap();
        memory.write_bytes(0x7000, &[0u8; 256]).unwrap();
        let rc = lane_syscall(
            dispatcher,
            memory,
            carrick_abi::CARRICK_PRIVATE_X86_NEWFSTATAT,
            [dirfd, 0x4000, 0x7000, flags, 0, 0],
        );
        let mode = if rc == 0 {
            u32::from_ne_bytes(
                memory
                    .read_bytes(0x7000 + 24, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        } else {
            0
        };
        (rc, mode)
    };

    let enotdir = -i64::from(crate::linux_abi::LINUX_ENOTDIR.get());
    let eloop = -i64::from(crate::linux_abi::LINUX_ELOOP.get());

    // 1. Plain path: /mydir/myfile
    let fd = call_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/myfile",
        LINUX_O_RDONLY,
    );
    assert!(fd >= 0, "openat plain path should succeed, got {fd}");
    let (rc, mode) = call_fstat(&mut dispatcher, &mut memory, fd as i32);
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o100000,
        "fstat plain path must be S_IFREG"
    );
    let (rc, mode) = call_x86_fstat(&mut dispatcher, &mut memory, fd as i32);
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o100000,
        "x86_fstat plain path must be S_IFREG"
    );
    lane_syscall(&mut dispatcher, &mut memory, 57, [fd as u64, 0, 0, 0, 0, 0]);

    let (rc, mode) = call_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/myfile",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_statx(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/myfile",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_stat(&mut dispatcher, &mut memory, "/mydir/myfile");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_lstat(&mut dispatcher, &mut memory, "/mydir/myfile");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/myfile",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);

    // 2. Trailing slash on file: /mydir/myfile/ (ENOTDIR)
    assert_eq!(
        call_openat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            "/mydir/myfile/",
            LINUX_O_RDONLY
        ),
        enotdir
    );
    assert_eq!(
        call_newfstatat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            "/mydir/myfile/",
            0
        )
        .0,
        enotdir
    );
    assert_eq!(
        call_statx(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            "/mydir/myfile/",
            0
        )
        .0,
        enotdir
    );
    assert_eq!(
        call_x86_stat(&mut dispatcher, &mut memory, "/mydir/myfile/").0,
        enotdir
    );
    assert_eq!(
        call_x86_lstat(&mut dispatcher, &mut memory, "/mydir/myfile/").0,
        enotdir
    );
    assert_eq!(
        call_x86_newfstatat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            "/mydir/myfile/",
            0
        )
        .0,
        enotdir
    );

    // Trailing slash on dir: /mydir/
    let dir_fd = call_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/",
        LINUX_O_RDONLY,
    );
    assert!(dir_fd >= 0, "openat /mydir/ should succeed");
    lane_syscall(
        &mut dispatcher,
        &mut memory,
        57,
        [dir_fd as u64, 0, 0, 0, 0, 0],
    );
    let (rc, mode) = call_newfstatat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, "/mydir/", 0);
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o040000, "must be S_IFDIR");
    let (rc, mode) = call_statx(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, "/mydir/", 0);
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o040000, "must be S_IFDIR");
    let (rc, mode) = call_x86_stat(&mut dispatcher, &mut memory, "/mydir/");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o040000, "must be S_IFDIR");
    let (rc, mode) = call_x86_lstat(&mut dispatcher, &mut memory, "/mydir/");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o040000, "must be S_IFDIR");
    let (rc, mode) =
        call_x86_newfstatat(&mut dispatcher, &mut memory, LINUX_AT_FDCWD, "/mydir/", 0);
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o040000, "must be S_IFDIR");

    // 3. /proc/self/... synthetic path: /proc/self/status
    let proc_fd = call_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/proc/self/status",
        LINUX_O_RDONLY,
    );
    assert!(proc_fd >= 0, "openat /proc/self/status should succeed");
    lane_syscall(
        &mut dispatcher,
        &mut memory,
        57,
        [proc_fd as u64, 0, 0, 0, 0, 0],
    );
    let (rc, mode) = call_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/proc/self/status",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_statx(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/proc/self/status",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_stat(&mut dispatcher, &mut memory, "/proc/self/status");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_lstat(&mut dispatcher, &mut memory, "/proc/self/status");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/proc/self/status",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);

    // 4. Escape above rootfs: /../../mydir/myfile (clamped to /mydir/myfile)
    let esc_fd = call_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/../../mydir/myfile",
        LINUX_O_RDONLY,
    );
    assert!(esc_fd >= 0, "openat /../../mydir/myfile should succeed");
    lane_syscall(
        &mut dispatcher,
        &mut memory,
        57,
        [esc_fd as u64, 0, 0, 0, 0, 0],
    );
    let (rc, mode) = call_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/../../mydir/myfile",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_statx(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/../../mydir/myfile",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_stat(&mut dispatcher, &mut memory, "/../../mydir/myfile");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_lstat(&mut dispatcher, &mut memory, "/../../mydir/myfile");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);
    let (rc, mode) = call_x86_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/../../mydir/myfile",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o100000);

    // 5. AT_SYMLINK_NOFOLLOW on a symlinked dir: /mydir/dirsym -> /mydir
    // Under AT_SYMLINK_NOFOLLOW: reports S_IFLNK
    let (rc, mode) = call_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        crate::linux_abi::LINUX_AT_SYMLINK_NOFOLLOW,
    );
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o120000,
        "newfstatat NOFOLLOW must report S_IFLNK"
    );
    let (rc, mode) = call_statx(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        crate::linux_abi::LINUX_AT_SYMLINK_NOFOLLOW,
    );
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o120000,
        "statx NOFOLLOW must report S_IFLNK"
    );
    let (rc, mode) = call_x86_lstat(&mut dispatcher, &mut memory, "/mydir/dirsym");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o120000, "x86_lstat must report S_IFLNK");
    let (rc, mode) = call_x86_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        crate::linux_abi::LINUX_AT_SYMLINK_NOFOLLOW,
    );
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o120000,
        "x86_newfstatat NOFOLLOW must report S_IFLNK"
    );
    // openat with O_NOFOLLOW on symlink to dir reports ELOOP
    assert_eq!(
        call_openat(
            &mut dispatcher,
            &mut memory,
            LINUX_AT_FDCWD,
            "/mydir/dirsym",
            LINUX_O_RDONLY | carrick_abi::LINUX_O_NOFOLLOW
        ),
        eloop,
        "openat O_NOFOLLOW on symlink to dir must report ELOOP"
    );

    // Without NOFOLLOW: reports S_IFDIR
    let (rc, mode) = call_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o040000,
        "newfstatat following must report S_IFDIR"
    );
    let (rc, mode) = call_statx(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o040000,
        "statx following must report S_IFDIR"
    );
    let (rc, mode) = call_x86_stat(&mut dispatcher, &mut memory, "/mydir/dirsym");
    assert_eq!(rc, 0);
    assert_eq!(mode & 0o170000, 0o040000, "x86_stat must report S_IFDIR");
    let (rc, mode) = call_x86_newfstatat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(
        mode & 0o170000,
        0o040000,
        "x86_newfstatat following must report S_IFDIR"
    );
    let open_follow_fd = call_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/mydir/dirsym",
        LINUX_O_RDONLY,
    );
    assert!(
        open_follow_fd >= 0,
        "openat following symlink to dir should succeed"
    );
    lane_syscall(
        &mut dispatcher,
        &mut memory,
        57,
        [open_follow_fd as u64, 0, 0, 0, 0, 0],
    );
}

struct FsViewFixture {
    fs: FsState,
    file_authority: RwLock<Option<Arc<crate::file_authority::FileAuthorityRun>>>,
    io: RuntimeIo,
    mm_binding: Arc<DispatchMmBinding>,
    proc: Mutex<proc::ProcState>,
    kernel_binding: RwLock<crate::kernel::KernelTaskBinding>,
    network: Arc<crate::network::RuntimeNetwork>,
    page_geometry: crate::page_profile::PageGeometry,
    task_context: crate::kernel::KernelContext,
}

impl FsViewFixture {
    fn new() -> Self {
        let (kernel_binding, mm_id) = crate::dispatch::kernel_context::bootstrap_one_task_binding();
        let task_context = kernel_binding
            .capture(crate::kernel::LinuxTid::for_task_leader(
                kernel_binding.task_id(),
            ))
            .expect("fixture kernel context");
        let mm_authority = Arc::new(DispatchMmAuthority::new(mm_id));
        Self {
            fs: FsState::new_with_host_resolver(None),
            file_authority: RwLock::new(None),
            io: RuntimeIo::new(),
            mm_binding: DispatchMmBinding::new(mm_authority),
            proc: Mutex::new(proc::ProcState::new()),
            kernel_binding: RwLock::new(kernel_binding),
            network: Arc::new(crate::network::RuntimeNetwork::host_default()),
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                linux_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                native_profile: None,
            },
            task_context,
        }
    }

    fn view(&self) -> FsView<'_> {
        FsView {
            fs: &self.fs,
            file_authority: &self.file_authority,
            io: &self.io,
            mm_binding: &self.mm_binding,
            proc: &self.proc,
            kernel_binding: &self.kernel_binding,
            network: &self.network,
            page_geometry: self.page_geometry,
            sysv: None,
            exec_host_fs_fallback: false,
            cross: self,
        }
    }
}

impl FsCrossSubsystem for FsViewFixture {
    fn captured_fs_context(&self) -> Arc<crate::kernel::FsContext> {
        self.task_context.resources().fs_context()
    }
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        self.task_context.resources().files()
    }
    fn captured_mm(&self) -> Arc<crate::kernel::Mm> {
        self.task_context.shared().mm()
    }
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.task_context.resources().credentials()
    }
    fn cwd(&self) -> String {
        self.task_context.resources().fs_context().cwd()
    }
    fn mem_snapshot(&self) -> crate::dispatch::mem::MemState {
        crate::dispatch::mem::MemState::new()
    }
    fn identity_pid(&self) -> u32 {
        1
    }
    fn sysvipc_shm_table(&self) -> String {
        String::from(
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n",
        )
    }
    fn sysvipc_sem_table(&self) -> String {
        String::from(
            "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
        )
    }
    fn sysvipc_msg_table(&self) -> String {
        String::from(
            "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
        )
    }
    fn captured_slot_authority(
        &self,
        fd: i32,
    ) -> Option<crate::kernel::objects::FileSlotAuthority> {
        let number = crate::kernel::FileSlotNumber::for_open_fd(fd).ok()?;
        self.captured_file_table().capture_slot_authority(number)
    }
}

#[test]
fn fs_view_direct_construction_and_operations() {
    let fixture = FsViewFixture::new();
    let view = fixture.view();

    // 1. Directory anchor resolution without a SyscallDispatcher
    let anchor = view
        .openat2_anchor_for_dirfd(carrick_abi::LINUX_AT_FDCWD as u64)
        .expect("openat2 anchor for AT_FDCWD");
    assert_eq!(anchor, "/");

    // 2. Duplicate stdio fd directly through FsView
    let dup_outcome = view.duplicate_fd(0, 0, 0);
    let new_fd = match dup_outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("expected returned fd, got {:?}", other),
    };
    assert!(
        new_fd >= 3,
        "duped fd must be allocated at or above 3, got {}",
        new_fd
    );
    assert!(view.fd_table_contains(new_fd));

    // 3. Stat the duped fd through FsView
    let stat = view
        .fd_stat_record(new_fd)
        .expect("fd_stat_record on duped fd");
    assert!(stat.mode != 0);

    // 4. Duplicate again with min_fd constraint
    let dup2_outcome = view.duplicate_fd(new_fd, 10, 0);
    let new_fd2 = match dup2_outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("expected returned fd, got {:?}", other),
    };
    assert!(new_fd2 >= 10, "duped fd must be >= 10, got {}", new_fd2);
    assert!(view.fd_table_contains(new_fd2));

    // 5. Test SyscallCtx handlers directly on FsView without SyscallDispatcher
    let context = view.capture_one_task_context().expect("context");
    let reporter = carrick_observability::compat::CompatReporter::default();
    let mut memory = crate::dispatch::LinearMemory::new(0, vec![0; 64]);

    // Test dup handler on FsView
    let mut dup_req = crate::dispatch::SyscallCtx {
        kernel: &context,
        request: crate::dispatch::SyscallRequest::new(
            23, // dup
            crate::dispatch::SyscallArgs::from([new_fd as u64, 0, 0, 0, 0, 0]),
        ),
        memory: &mut memory,
        reporter: &reporter,
        thread: None,
        execution_lease: None,
        mm_executor: None,
    };
    let handler_dup_outcome = resources::with_captured_resources(&context, || {
        view.dup(&mut dup_req).expect("dup handler on FsView")
    });
    let new_fd3 = match handler_dup_outcome {
        DispatchOutcome::Returned { value } => value as i32,
        other => panic!("expected returned fd from dup handler, got {:?}", other),
    };
    assert!(new_fd3 >= 3);
    assert!(view.fd_table_contains(new_fd3));

    // Test close handler on FsView
    let mut close_req = crate::dispatch::SyscallCtx {
        kernel: &context,
        request: crate::dispatch::SyscallRequest::new(
            57, // close
            crate::dispatch::SyscallArgs::from([new_fd3 as u64, 0, 0, 0, 0, 0]),
        ),
        memory: &mut memory,
        reporter: &reporter,
        thread: None,
        execution_lease: None,
        mm_executor: None,
    };
    let handler_close_outcome = resources::with_captured_resources(&context, || {
        view.close(&mut close_req).expect("close handler on FsView")
    });
    assert_eq!(
        handler_close_outcome,
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(!view.fd_table_contains(new_fd3));
}

#[cfg(target_os = "macos")]
#[test]
fn tty0_two_opens_share_termios_and_winsize() {
    let (_lower, _upper, mut dispatcher) = trusted_lower_lane_fixture();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x10000]);

    // Open /dev/tty0 twice
    let fd1 = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/dev/tty0",
        LINUX_O_RDWR,
    );
    assert!(fd1 >= 0, "first open of /dev/tty0 should succeed: {fd1}");

    let fd2 = lane_openat(
        &mut dispatcher,
        &mut memory,
        LINUX_AT_FDCWD,
        "/dev/tty0",
        LINUX_O_RDWR,
    );
    assert!(fd2 >= 0, "second open of /dev/tty0 should succeed: {fd2}");
    assert_ne!(fd1, fd2, "independent opens should yield different fds");

    // Check fstat reports character device with major 4 minor 0
    let stat_buf = [0u8; core::mem::size_of::<carrick_abi::LinuxStat>()];
    memory.write_bytes(0x5000, &stat_buf).unwrap();
    let fstat_rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        80, // fstat
        [fd1 as u64, 0x5000, 0, 0, 0, 0],
    );
    assert_eq!(fstat_rc, 0);
    let stat = carrick_abi::LinuxStat::read_from_bytes(
        &memory.read_bytes(0x5000, stat_buf.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        stat.st_mode & carrick_abi::LINUX_S_IFMT,
        carrick_abi::LINUX_S_IFCHR
    );
    let rdev = stat.st_rdev;
    assert_eq!(rdev, 4 << 8);

    // Write a customized termios struct to memory at 0x6000
    let mut custom = carrick_abi::LinuxTermios::default_cooked();
    custom.c_iflag = 0x1234_5678;
    custom.c_oflag = 0x8765_4321;
    let custom_bytes = zerocopy::IntoBytes::as_bytes(&custom);
    memory.write_bytes(0x6000, custom_bytes).unwrap();

    // TCSETS via fd1
    let set_rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        29, // ioctl
        [fd1 as u64, carrick_abi::LINUX_TCSETS, 0x6000, 0, 0, 0],
    );
    assert_eq!(set_rc, 0, "TCSETS via fd1 should return 0");

    // TCGETS via fd2 into 0x7000
    let get_rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        29, // ioctl
        [fd2 as u64, carrick_abi::LINUX_TCGETS, 0x7000, 0, 0, 0],
    );
    assert_eq!(get_rc, 0, "TCGETS via fd2 should return 0");

    let read_termios = carrick_abi::LinuxTermios::read_from_bytes(
        &memory
            .read_bytes(0x7000, core::mem::size_of::<carrick_abi::LinuxTermios>())
            .unwrap(),
    )
    .unwrap();
    let (iflag, oflag) = (read_termios.c_iflag, read_termios.c_oflag);
    assert_eq!(iflag, 0x1234_5678, "fd2 should observe termios set by fd1");
    assert_eq!(oflag, 0x8765_4321, "fd2 should observe termios set by fd1");

    // TIOCSWINSZ via fd1 into 0x8000
    let mut custom_ws = carrick_abi::LinuxWinsize::terminal_80x24();
    custom_ws.ws_row = 50;
    custom_ws.ws_col = 132;
    let ws_bytes = zerocopy::IntoBytes::as_bytes(&custom_ws);
    memory.write_bytes(0x8000, ws_bytes).unwrap();

    let set_ws_rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        29, // ioctl
        [fd1 as u64, carrick_abi::LINUX_TIOCSWINSZ, 0x8000, 0, 0, 0],
    );
    assert_eq!(set_ws_rc, 0, "TIOCSWINSZ via fd1 should return 0");

    // TIOCGWINSZ via fd2 into 0x9000
    let get_ws_rc = lane_syscall(
        &mut dispatcher,
        &mut memory,
        29, // ioctl
        [fd2 as u64, carrick_abi::LINUX_TIOCGWINSZ, 0x9000, 0, 0, 0],
    );
    assert_eq!(get_ws_rc, 0, "TIOCGWINSZ via fd2 should return 0");

    let read_ws = carrick_abi::LinuxWinsize::read_from_bytes(
        &memory
            .read_bytes(0x9000, core::mem::size_of::<carrick_abi::LinuxWinsize>())
            .unwrap(),
    )
    .unwrap();
    let (ws_row, ws_col) = (read_ws.ws_row, read_ws.ws_col);
    assert_eq!(ws_row, 50, "fd2 should observe winsize set by fd1");
    assert_eq!(ws_col, 132, "fd2 should observe winsize set by fd1");
}
