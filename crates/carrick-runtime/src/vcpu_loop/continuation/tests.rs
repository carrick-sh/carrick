//! Carrier-side tests of the kernel continuation model: the six that name
//! `crate::hvpatch`, the neutral host pending store, or executor internals, and so stay
//! with the carrier while the model itself lives in
//! `carrick_kernel::kernel::continuation`.

use std::sync::Arc;

use carrick_abi::{LinuxCloneFlags, SigSet, WaitSigMask};
use carrick_hal::ThreadId;

use crate::compat::SyscallArgs;
use carrick_kernel::dispatch::{DispatchOutcome, FdWaitCompletion, SyscallRequest, WaitFds};
use carrick_kernel::kernel::continuation::test_support::{
    DISPATCH_FAMILIES, await_event, bootstrap, capture, publish,
};
use carrick_kernel::kernel::continuation::*;
use carrick_kernel::kernel::{ClonePlan, Scheduler};

#[test]
fn hvpatch_launch_callgraph_never_constructs_the_compatibility_loop_future() {
    let source = include_str!("../binding.rs");
    // INVERTED for the fork-closure deletion. This used to bound the launch
    // entry between `launch_vcpu_until_exit` and `PreparedInitialRunnerTask`
    // and assert the HVPatch arm came first. Both are deleted: there is no
    // compatibility launch entry left to come second, so the invariant is
    // now that none of that text exists at all. Asserting ABSENCE is the
    // only form that keeps gating once the text is gone — a `split_once` on
    // absent text would hand the whole file to the next assertion.
    for deleted in [
        "fn launch_vcpu_until_exit",
        "fn launch_compatibility_vcpu_future",
        "fn run_vcpu_until_exit",
        "fn run_vcpu_until_exit_inner",
    ] {
        assert!(
            !source.contains(deleted),
            "the welded-thread vCPU loop is retired; `{deleted}` must not exist"
        );
    }
    // `prepare_initial_runner_handoff` and its `PreparedInitialRunnerTask`
    // are NOT part of that chain: `launch_persistent_hvpatch_job` calls them
    // to publish the initial task state and claim its start gate. Deleting
    // them with the welded loop was caught by the compiler, not by a test.
    for shared in [
        "fn prepare_initial_runner_handoff",
        "struct PreparedInitialRunnerTask",
    ] {
        assert!(
            source.contains(shared),
            "the persistent launcher's initial handoff `{shared}` must survive"
        );
    }
    let logical_job = source
        .split_once("fn prepare_hvpatch_logical_job")
        .expect("reusable logical-job constructor")
        .1
        .split_once("fn launch_persistent_hvpatch_job")
        .expect("end of reusable logical-job constructor")
        .0;
    for required in [
        "HvpatchLoopJob::production",
        "HvpatchTaskBinding::new_with_stage1_mm",
    ] {
        assert!(
            logical_job.contains(required),
            "reusable HVPatch logical-job constructor omitted {required}"
        );
    }
    let persistent = source
        .split_once("fn launch_persistent_hvpatch_job")
        .expect("persistent HVPatch launcher")
        .1
        .split_once("fn trap_watchdog_decision")
        .expect("end of persistent launcher")
        .0;
    for prohibited in [
        "run_vcpu_until_exit_inner",
        "OwnerThreadEngine",
        "std::thread::Builder",
    ] {
        assert!(
            !persistent.contains(prohibited),
            "persistent HVPatch launch retained compatibility authority {prohibited}"
        );
    }
    for required in [
        "prepare_hvpatch_logical_job",
        "prepare_submission",
        "start_persistent_pool",
        "dormant.activate",
    ] {
        assert!(
            persistent.contains(required),
            "persistent HVPatch launch omitted production edge {required}"
        );
    }
    let proof = persistent
        .find("logical.activation_proof()")
        .expect("consumed Kernel start-gate proof");
    let start = persistent
        .find("start_persistent_pool(")
        .expect("pool start");
    let activate = persistent
        .find("dormant.activate")
        .expect("queue activation");
    let rollback = persistent
        .find("if started_pool")
        .expect("new-pool-only rollback guard");
    let shutdown = persistent
        .find("shutdown_persistent_pool()")
        .expect("new pool close/join rollback");
    assert!(proof < start && start < activate && activate < rollback && rollback < shutdown);

    let executor_source = include_str!("../executor/binding.rs");
    let worker_prepare = executor_source
        .split_once("fn prepare_hvpatch_submission")
        .expect("worker-held HVPatch preparation API")
        .1
        .split_once("pub trait TaskBindingResolver")
        .expect("end of worker-held preparation API")
        .0;
    assert!(worker_prepare.contains("self.current"));
    assert!(worker_prepare.contains("Some(current)"));
    assert!(!worker_prepare.contains("bindings.get(&grant)"));
}

#[test]
fn static_hvpatch_continuation_closure_forbids_host_blocking_authority() {
    let continuation_source = include_str!("../../../../carrick-kernel/src/kernel/continuation.rs")
        .split("#[cfg(test)]\npub(crate) mod tests")
        .next()
        .expect("production continuation source");
    for prohibited in [
        "libc::wait",
        "libc::waitpid",
        "libc::kill",
        "libc::nanosleep",
        "ThreadWaiter",
        "make_readiness_pipe",
        "wait_for_event",
        "Duration::from_millis(2)",
        "Duration::from_secs(24 * 60 * 60)",
    ] {
        assert!(
            !continuation_source.contains(prohibited),
            "HVPatch continuation path retains prohibited host-blocking authority: {prohibited}"
        );
    }
    // 18 dispatch-produced families + `VforkParent`. The retained
    // `BlockingOpen` family owns a descriptor reservation while a FIFO open
    // is parked. It was 20 until the
    // host-pid `WaitOnProcExit`/`WaitOnProcState` families went with the
    // retired 1:1 native lane; their event codes (12, 13) stay retired rather
    // than being renumbered, so this census is the family COUNT, not the code
    // range.
    assert_eq!(DISPATCH_FAMILIES.len() + 1, 19);
    // The retired 1:1 native lane's host-pid wait is gone from the
    // continuation path: no outcome, no family, no selector, and no
    // "reject a host wait on HVPatch" guard, because the types can no longer
    // spell a Darwin pid here at all.
    for deleted in [
        "WaitOnProcExit",
        "WaitOnProcState",
        "HostPid",
        "HostProcessWaitOnHvpatch",
    ] {
        assert!(
            !continuation_source.contains(deleted),
            "the retired native lane's host-pid wait is deleted; `{deleted}` must not exist"
        );
    }
    // The transitional runner pool and its ambient thread-locals are gone.
    // Nothing on the persistent executor ever published them, so every read
    // already answered None/false; they are deleted rather than left as a
    // second, silently-inert executor identity.
    for deleted in [
        "TransitionalDedicatedRunner",
        "TransitionalRunnerPool",
        "TransitionalWorkerContext",
        "TransitionalWorkerKick",
        "run_task_quantum",
        "CURRENT_RUNNER_WORKER",
        "CURRENT_RUNNER_JOB",
        "LogicalTaskReceipt",
    ] {
        assert!(
            !continuation_source.contains(deleted),
            "the transitional runner pool is retired; `{deleted}` must not exist"
        );
    }
    assert!(!continuation_source.contains("TaskQuantumSource"));
    assert!(!continuation_source.contains("fallback_fd"));
    // REPOINTED for the fork-closure deletion. `scheduler.request_preemption()`
    // was the transitional pool's carrier-timer policy hook and its only
    // production caller; the persistent executor owns preemption itself
    // through its own `need_resched` flag, so the invariant is asserted
    // where it now lives.
    let executor_source = include_str!("../executor/pool.rs");
    assert!(
        executor_source.contains("self.need_resched.store(true, Ordering::Release);"),
        "the persistent executor must own its own preemption request"
    );

    let loop_source = include_str!("../mod.rs");
    let prepare_suspend = loop_source
        .split("fn prepare_hvpatch_continuation")
        .nth(1)
        .and_then(|tail| tail.split("fn persistent_block_exit").next())
        .expect("engine-free HVPatch continuation preparation");
    for required in [
        "ContinuationCapture::from_lease",
        "BlockedContinuation::from_dispatch_outcome",
        "BlockedContinuation::from_vfork_parent",
        "install_temporary_signal_mask",
    ] {
        assert!(
            prepare_suspend.contains(required),
            "engine-free continuation preparation misses {required}"
        );
    }
    // INVERTED for the fork-closure deletion. The engine-owning welded loop
    // and its `suspend_hvpatch_continuation` adapter used to be bounded and
    // inspected here for product boundaries and prohibited host-blocking
    // authority. `launch_vcpu_until_exit` returned unconditionally at its
    // first statement, so none of that ran; the persistent executor reaches
    // the same continuation through `persistent_block_exit`. The surviving
    // invariant is that the welded chain does not exist at all.
    for deleted in [
        "fn suspend_hvpatch_continuation",
        "async fn yield_hvpatch_quantum",
        "fn run_vcpu_until_exit",
        "fn launch_vcpu_until_exit",
        "struct OwnerThreadEngine",
        "enum CompatibilityThreadWaiter",
    ] {
        assert!(
            !loop_source.contains(deleted),
            "the welded-thread vCPU loop is retired; `{deleted}` must not exist"
        );
    }
    let dispatch = loop_source
        .split("fn redispatch_threaded_syscall_for_executor")
        .nth(1)
        .and_then(|tail| tail.split("\n    fn ").next())
        .expect("dispatch service body");
    assert!(
        dispatch.contains("continuation::is_blocking_dispatch_outcome(&outcome)"),
        "HVPatch must still escape a blocking outcome at the dispatch seam"
    );
    let quiesce = include_str!("../quiesce.rs");
    let hvpatch_fork = quiesce
        .split("fn prepare_in_process_fork")
        .nth(1)
        .and_then(|tail| tail.split("#[cfg(test)]").next())
        .expect("HVPatch fork body");
    assert!(hvpatch_fork.contains("PreparedInProcessFork::SuspendVfork"));
    assert!(!hvpatch_fork.contains(".await"));
    assert!(!hvpatch_fork.contains("wait.wait_for_release"));
    let binding = include_str!("../binding.rs");
    let fork_wrapper = binding
        .split("fn complete_persistent_process_fork")
        .nth(1)
        .and_then(|tail| tail.split("fn finalize_persistent_process_terminal").next())
        .expect("persistent fork suspension wrapper");
    assert!(fork_wrapper.contains("HvpatchBlockInput::Vfork"));

    let threads = include_str!("../threads.rs");
    // INVERTED for the fork-closure deletion. This clause used to bound the
    // exec drain by the retired pool's ambient job thread-local and inspect
    // the executor-lease drain inside it. Only that pool ever published the
    // thread-local — never the persistent executor — so the branch never
    // ran, and the bounded drain beside it is the one that has always
    // executed. The surviving invariant is that guest-thread teardown
    // reacquires no retired runner identity.
    for deleted in [
        "TransitionalDedicatedRunner",
        "TransitionalWorkerContext",
        "await_hvpatch_sibling_jobs",
    ] {
        assert!(
            !threads.contains(deleted),
            "guest-thread teardown retains retired runner authority {deleted}"
        );
    }

    // Anchored on the reactor itself rather than on the Nth textual
    // occurrence of `ReadinessProbe::RecordLock`: an occurrence index
    // silently reaims at unrelated code the moment another match arm on
    // that variant is added anywhere earlier in the file (the diagnostic
    // renderer did exactly that), and a test that reaims is worse than no
    // test. This region is exactly the reactor body.
    let wait_service_source =
        include_str!("../../../../carrick-kernel/src/kernel/continuation/wait_service.rs");
    let record_reactor = wait_service_source
        .split("fn run_reactor")
        .nth(1)
        .and_then(|tail| tail.split("impl Drop for CarrierWaitServiceInner").next())
        .expect("shared record-lock reactor path");
    assert!(record_reactor.contains("try_drive_blocking_record_lock"));
    for prohibited in [
        "carrick_kernel::dispatch::drive_blocking_record_lock(",
        "F_SETLKW",
        "Condvar",
    ] {
        assert!(
            !record_reactor.contains(prohibited),
            "record-lock reactor retains blocking authority {prohibited}"
        );
    }

    let signal_source = include_str!("../signal.rs");
    assert!(signal_source.contains("deliver_pending_signal_with_restart"));
    assert!(loop_source.contains("continuation.install_temporary_signal_mask(context)"));
    // The resume path must stash the restart decision — but ONLY for a
    // completion the signal path itself produced. A Ready->Redispatch
    // resume stashing its default NoRestart vetoed SA_RESTART for the
    // redispatched syscall's own EINTR (waitrestart scenario A).
    assert!(loop_source.contains("self.continuation_restart = match result.completion"));
    assert!(loop_source.contains("=> Some(result.restart()),"));
    assert!(loop_source.contains("ContinuationResumeError::StaleFileSlot"));
    assert!(!loop_source.contains("TransitionalSchedulerKick"));
    assert!(!loop_source.contains("continuation_executor"));

    let net_source = include_str!("../../../../carrick-kernel/src/dispatch/net.rs");
    assert!(
        net_source.matches("this.assemble_wait(").count() >= 2,
        "pselect/ppoll must go through the ONE wait assembly, which classifies \
         every guest fd into a registration carrying both its host half and its \
         exact slot"
    );
    let wait_plan_source = include_str!("../../../../carrick-kernel/src/dispatch/wait_plan.rs");
    assert!(
        wait_plan_source.contains("self.wait_source_for(files, entry.fd, entry.requested)"),
        "the assembly classifies every requested fd at dispatch"
    );
    assert!(
        !net_source.contains("fn host_poll_target")
            && !net_source.contains("fn wait_target_for_poll"),
        "the two independently built wait lists and their -1 sentinel are retired"
    );
    let io_uring_source = include_str!("../../../../carrick-kernel/src/dispatch/ioring.rs");
    assert!(io_uring_source.contains("with_guest_slots(&files, [ring_fd, sqe.fd])"));
    // RETIRED with the 1:1 native lane's host-pid wait bodies: the only
    // `WaitFds` producer in `dispatch/proc.rs` was the retired lane's
    // `waitid(P_PIDFD)` park on a host pidfd, so there is no proc.rs fd
    // producer left to hold to this invariant. An `include_str!` clause whose
    // subject no longer exists is a test that reaims, so it is deleted rather
    // than loosened; the HVPatch `waitid` parks on the kernel graph
    // (`WaitOnHvpatchChild`), which carries no host fd at all.
    let proc_source = include_str!("../../../../carrick-kernel/src/dispatch/proc.rs");
    assert!(
        !proc_source.contains("WaitFds"),
        "proc.rs must not reintroduce a host-fd wait producer"
    );
    let fs_source = include_str!("../../../../carrick-kernel/src/dispatch/fs.rs");
    assert!(!fs_source.contains("WaitFdAuthority::Missing"));
    for required in [
        "captured_slot_authority(guest_fd)",
        "captured_slot_authority(fd)",
        "captured_slot_authority(fd.0)",
        "WaitFdAuthority::logical",
        "[in_fd.0, out_fd.0]",
        "complete_wait_fd_authority",
    ] {
        assert!(
            fs_source.contains(required),
            "fd producer misses {required}"
        );
    }
}

#[test]
fn logical_group_wait_dispatch_builds_an_any_child_continuation() {
    let _lane = carrick_kernel::dispatch::HvpatchLaneScope::force(false);
    let (process, root) = crate::hvpatch::process_context_for_tests(15_025);
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    dispatcher.bind_hvpatch_process(Arc::new(process));
    let _child = root
        .kernel()
        .reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
            "group-wait-child".to_owned(),
            None,
        )
        .unwrap()
        .prepare_reference(ThreadId::synthetic_for_tests(15_026))
        .unwrap()
        .commit()
        .unwrap()
        .into_parts()
        .unwrap()
        .0;
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();
    let generation = publish(&root, 0x325);
    let mut memory = carrick_kernel::dispatch::LinearMemory::new(0x4000, vec![0; 0x100]);
    let outcome = dispatcher
        .dispatch(
            &root,
            SyscallRequest::new(260, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &crate::compat::CompatReporter::default(),
        )
        .unwrap();
    assert!(matches!(
        &outcome,
        DispatchOutcome::WaitOnHvpatchChild { target: None, .. }
    ));
    let continuation =
        BlockedContinuation::from_dispatch_outcome(outcome, capture(&root, generation))
            .expect("group wait must build without StaleChildSelector");
    assert_eq!(
        continuation.child_selector(),
        Some(ChildSelector::AnyChildOf(root.task().key()))
    );
}

#[test]
fn host_slot_signal_is_reserved_and_cancelled_into_exact_kernel_ownership() {
    let (_kernel, context) = bootstrap(153_693);
    let generation = publish(&context, 0x708);
    let signal = carrick_kernel::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let persistent = SigSet::EMPTY.with(10);
    context.signal_authority().set_blocked(persistent);
    let mut action = carrick_abi::LinuxSigaction::empty();
    action.sa_handler = 0x3330;
    context.signal_authority().install_action(signal, action);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation),
    )
    .expect("continuation");
    let tid = context.thread().key().tid.raw();
    carrick_signal_core::publish_pending_for(tid, 10);
    let event = SignalReadinessProbe::from_continuation(&continuation)
        .event()
        .expect("host-slot readiness reservation");
    assert_eq!(event.reserved_signal().expect("reservation").signum(), 10);
    drop(event);
    assert_eq!(
        carrick_signal_core::take_pending_for(tid),
        0,
        "imported host ownership is not duplicated back into the lossy host bitmask"
    );
    let replay = context
        .signal_authority()
        .reserve_deliverable_for_wait(WaitSigMask::Replace(SigSet::EMPTY))
        .expect("abandoned reservation remains exact in Kernel pending state");
    assert_eq!(replay.signum(), 10);
    assert_eq!(replay.action(), action);
}

#[test]
fn realtime_host_slot_import_preserves_fifo_multiplicity_and_exact_cancellation_requeue() {
    let (kernel, context) = bootstrap(15_468);
    let generation = publish(&context, 0x913);
    drop(kernel);
    let rt_a = carrick_kernel::kernel::LinuxSignal::for_signal_number(32).expect("SIGRTMIN");
    let rt_b = carrick_kernel::kernel::LinuxSignal::for_signal_number(33).expect("SIGRTMIN+1");
    for signal in [rt_a, rt_b] {
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x9000 + signal.raw() as u64;
        context.signal_authority().install_action(signal, action);
    }
    let first =
        crate::linux_abi::LinuxSiginfo::kill(32, crate::linux_abi::LINUX_SI_TKILL, 101, 201);
    let second =
        crate::linux_abi::LinuxSiginfo::kill(32, crate::linux_abi::LINUX_SI_TKILL, 102, 202);
    let other =
        crate::linux_abi::LinuxSiginfo::kill(33, crate::linux_abi::LINUX_SI_TKILL, 103, 203);
    let action_a = context.signal_authority().action(rt_a);
    let action_b = context.signal_authority().action(rt_b);
    context.thread().update_signal_state(|state| {
        state.record_routed_siginfo(rt_a, first);
        state.record_routed_siginfo(rt_a, second);
        state.record_routed_siginfo(rt_b, other);
        state.record_pending_action(rt_a, action_a);
        state.record_pending_action(rt_a, action_a);
        state.record_pending_action(rt_b, action_b);
    });
    let tid = context.thread().key().tid.raw();
    carrick_signal_core::publish_pending_for(tid, 32);
    carrick_signal_core::publish_pending_for(tid, 32);
    carrick_signal_core::publish_pending_for(tid, 33);

    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation),
    )
    .expect("suspended RT continuation");
    let event = SignalReadinessProbe::from_continuation(&continuation)
        .event()
        .expect("first RT readiness");
    let reserved = event.reserved_signal().expect("first RT reservation");
    assert_eq!(reserved.signum(), 32);
    assert_eq!(reserved.siginfo(), Some(first));
    assert_eq!(reserved.host_slot_tid(), Some(tid));
    let result = continuation
        .resume(event, &context)
        .expect("resume first RT interruption");
    drop(result);

    let replay = context
        .signal_authority()
        .reserve_deliverable_for_wait(WaitSigMask::NONE)
        .expect("cancelled first RT requeues exactly");
    let replay = ReservedSignal::from_kernel_reservation(context.signal_authority(), replay);
    assert_eq!(replay.siginfo(), Some(first));
    assert!(replay.consume());
    let second_reserved = context
        .signal_authority()
        .reserve_deliverable_for_wait(WaitSigMask::NONE)
        .expect("second same-signum RT instance remains queued");
    let second_reserved =
        ReservedSignal::from_kernel_reservation(context.signal_authority(), second_reserved);
    assert_eq!(second_reserved.signum(), 32);
    assert_eq!(second_reserved.siginfo(), Some(second));
    assert!(second_reserved.consume());

    let next = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation),
    )
    .expect("next suspended RT continuation");
    let next_event = SignalReadinessProbe::from_continuation(&next)
        .event()
        .expect("other RT signum readiness");
    let next_reserved = next_event.reserved_signal().expect("other RT reservation");
    assert_eq!(next_reserved.signum(), 33);
    assert_eq!(next_reserved.siginfo(), Some(other));
    assert!(
        context
            .thread()
            .update_signal_state(|state| state.pending_actions().is_empty())
    );
}

#[test]
fn kernel_native_guest_signal_continuation_cancels_and_delivers_without_host_sidecars() {
    let (kernel, context) = bootstrap(15_469);
    let generation = publish(&context, 0x914);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation),
    )
    .expect("guest-signal continuation");
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll guest-signal continuation");
    let wake_token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach guest-signal registration");
    let signal = carrick_kernel::kernel::LinuxSignal::for_signal_number(32).expect("SIGRTMIN");
    let info = crate::linux_abi::LinuxSiginfo::kill(
        32,
        crate::linux_abi::LINUX_SI_TKILL,
        context.task().key().id.raw(),
        context.resources().credentials().ruid().raw(),
    );
    let ticket = match kernel.authorize_signal_target_exact(
        &context,
        context.task().key(),
        Some(context.thread().key()),
        Some(signal),
    ) {
        carrick_kernel::kernel::ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
        other => panic!("exact guest signal ticket: {other:?}"),
    };
    assert_eq!(
        kernel.post_guest_thread_signal_to_authorized_target(&ticket, signal, Some(info)),
        carrick_kernel::kernel::ExactThreadSignalPost::Posted(Some(context.thread().key()))
    );
    assert_eq!(
        carrick_signal_core::take_pending_for(context.thread().key().tid.raw()),
        0
    );
    let event = await_event(&service, wake_token).expect("Kernel-native guest signal readiness");
    let reserved = event.reserved_signal().expect("exact guest reservation");
    assert_eq!(reserved.siginfo(), Some(info));
    assert_eq!(reserved.host_slot_tid(), None);
    let mut result = continuation
        .resume(event, &context)
        .expect("guest signal resume");
    let cancelled = result
        .take_reserved_signal()
        .expect("continuation owns exact reservation");
    drop(result);
    drop(cancelled);
    assert!(context.signal_authority().thread_pending().contains(32));

    let replay = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation),
    )
    .expect("replay continuation");
    let replay_event = SignalReadinessProbe::from_continuation(&replay)
        .event()
        .expect("cancelled exact instance replays");
    let replay_reserved = replay_event
        .reserved_signal()
        .expect("replayed reservation");
    assert_eq!(replay_reserved.siginfo(), Some(info));
    assert!(replay_reserved.consume());
    assert!(!replay_reserved.consume());
}
