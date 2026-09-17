//! The bring-your-own-execution-backend surface, consumed from OUTSIDE the
//! crate.
//!
//! `carrick-kernel` exists so an execution backend other than carrick-runtime's
//! HVPatch carrier can drive the kernel. Whether that is true is not a property
//! of how many items say `pub`: it is whether the exact items such a backend
//! needs are REACHABLE from another crate, and stay reachable. An integration
//! test links the kernel as an external crate (and gets `test-support` through
//! the self dev-dependency, because `tests/` sees no `cfg(test)`), so this file
//! sits in exactly a backend author's position — a `pub` that regresses to
//! `pub(crate)`, or a module that stops being public, fails it at COMPILE time
//! rather than at the next crate's creation.
//!
//! What it exercises, with no VM, no host fork and no guest code:
//!
//!   1. A dispatcher built on the `carrick-hal` Null bridges — assembled here
//!      from `CarrierBridges`' own public fields, NOT via
//!      `carrick_runtime::platform_bridges()`, which a non-carrier backend must
//!      not depend on — serving a real syscall through `LinearMemory`.
//!   2. A root task booted from `RootBootstrap` over a caller-supplied
//!      `MmBackend`, then a process fork carried through the public kernel
//!      operations (`reserve_fork` -> `PreparedFork` -> `PublishedFork` ->
//!      child `KernelContext`) and reaped through `wait_child`.
//!   3. The `CarrierProcess` double, reached through the trait, as the shape a
//!      backend implements for its own process handle.
//!
//! It is specifically the check on the kernel's PROMOTED `test-support`
//! doubles -- `TestCarrierProcess`, `TestMmBackend`, `TestStage1MmProjection`,
//! `test_mm_binding`, and the Null bridges they pair with -- from outside the
//! crate. That matters because `cfg(test)` is not set for an integration
//! target: the doubles reach this file only through the feature and the self
//! dev-dependency, which is the same path `carrick-runtime`'s suites take, so a
//! double that regresses to `pub(crate)` or loses its gate breaks here first.
//!
//! It is NOT a check on what `crates/carrick-kernel-example` consumes: the
//! example takes `carrick-kernel` with no features and brings its OWN
//! `CarrierProcess` / `MmBackend` / `Stage1MmProjection` impls, which is the
//! bring-your-own-backend point. Its `tests/fork_pipe_wait.rs` is the standing
//! check on the ungated public surface; this file is the standing check on the
//! gated doubles.

use std::sync::Arc;

use carrick_abi::syscall::lookup_aarch64;
use carrick_abi::{LinuxCloneFlags, WaitSigMask};
use carrick_guest_mem::{CurrentMmMemory, Gpa, GuestMemory};
use carrick_hal::stage1_mm::Stage1MmProjection;
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge};
use carrick_kernel::compat::{CompatReporter, SyscallArgs};
use carrick_kernel::dispatch::{
    CarrierBridges, DispatchOutcome, FdWaitCompletion, LinearMemory, SyscallDispatcher,
    SyscallRequest, WaitFds,
};
use carrick_kernel::kernel::operations::PreparedFork;
use carrick_kernel::kernel::{
    CarrierProcess, ChildWaitPrecheck, ClonePlan, Kernel, KernelContext, LinuxWaitStatus,
    MmBackend, PublishedFork, RootBootstrap, TaskKey, TestCarrierProcess, TestMmBackend,
    TestStage1MmProjection, WaitMode, test_mm_binding,
};
use carrick_kernel::thread::ThreadId;

/// The bound `SyscallDispatcher::dispatch` puts on a backend's guest memory.
/// A backend that cannot satisfy it cannot dispatch, so this is the contract
/// the example crate's `Vec`-backed memory has to meet; `LinearMemory` is the
/// kernel's own witness that the bound is satisfiable from outside.
fn dispatch_ready_memory<M: CurrentMmMemory>(memory: &M) -> bool {
    GuestMemory::has_complete_mapping_metadata(memory)
}

/// The wait PAYLOADS a backend's `on_wait` / `on_wait_fds` arms have to read.
/// Matching a variant proves only its name; naming the types it carries is what
/// proves a wait-capable backend can be written one crate away, so these two
/// extractors exist to name them. Their compile is the assertion.
fn fd_wait_shape(outcome: &DispatchOutcome) -> Option<(&WaitFds, &WaitSigMask, &FdWaitCompletion)> {
    match outcome {
        DispatchOutcome::WaitOnFds {
            fds,
            sig_mask,
            completion,
            ..
        } => Some((fds, sig_mask, completion)),
        _ => None,
    }
}

fn child_wait_shape(
    outcome: &DispatchOutcome,
) -> Option<(Option<i32>, &WaitSigMask, &ChildWaitPrecheck)> {
    match outcome {
        DispatchOutcome::WaitOnHvpatchChild {
            target,
            sig_mask,
            precheck,
        } => Some((*target, sig_mask, precheck)),
        _ => None,
    }
}

/// Every `DispatchOutcome` a VM-less backend has to interpret, named. A renamed
/// or removed variant fails this file to compile — which is the point: these
/// are the arms an external backend's run loop is written against.
fn outcome_kind(outcome: &DispatchOutcome) -> &'static str {
    match outcome {
        DispatchOutcome::Returned { .. } => "returned",
        DispatchOutcome::Errno { .. } => "errno",
        DispatchOutcome::Exit { .. } => "exit",
        DispatchOutcome::Fork { .. } => "fork",
        DispatchOutcome::WaitOnHvpatchChild { .. } => "wait-on-hvpatch-child",
        DispatchOutcome::WaitOnFds { .. } => "wait-on-fds",
        DispatchOutcome::SchedulerYield => "scheduler-yield",
        _ => "other",
    }
}

#[test]
fn hal_null_bridges_boot_a_dispatcher_that_serves_a_syscall() {
    // The carrier hands its dispatcher real bridges; a backend with no host
    // signal source or timer wheel hands it these. Built field-by-field on
    // purpose: it proves `CarrierBridges` is CONSTRUCTIBLE out-of-crate, not
    // merely nameable through `CarrierBridges::null()`.
    let bridges = CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(NullGuestTimerBridge::default()),
    };
    let mut dispatcher = SyscallDispatcher::with_bridges(bridges);
    let context = dispatcher
        .capture_one_task_context()
        .expect("a bridge-less dispatcher bootstraps a one-task kernel context");

    let mut memory = LinearMemory::new(0x4000, Vec::new());
    assert!(
        !dispatch_ready_memory(&memory),
        "the modelless in-memory backend publishes no complete protection map"
    );

    // Derive the syscall number from the ABI table rather than hardcoding it,
    // so the probe names `carrick_abi::syscall` the way a backend does.
    let getpid = lookup_aarch64(172).expect("aarch64 syscall 172 is in the table");
    assert_eq!(getpid.name, "getpid");

    let reporter = CompatReporter::default();
    let outcome = dispatcher
        .dispatch(
            &context,
            SyscallRequest::new(172, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .expect("getpid dispatches on a bridge-less dispatcher");

    assert_eq!(outcome_kind(&outcome), "returned");
    assert!(fd_wait_shape(&outcome).is_none());
    assert!(child_wait_shape(&outcome).is_none());
    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: i64::from(std::process::id() as i32)
        },
        "the bootstrap task reports the host pid, exactly as the in-crate suite sees it"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn a_backend_boots_a_root_and_forks_through_public_kernel_operations() {
    // A backend brings its own mm backend and its own stage-1 projection. The
    // test-support doubles stand in for a real one here; what is being proved
    // is that the SEAM (RootBootstrap over `Arc<dyn MmBackend>`) is reachable
    // and that the fork operations complete on it.
    let binding = test_mm_binding(1, 0x4000);
    let stage1 = Arc::new(TestStage1MmProjection::new(binding));
    let projection: &dyn Stage1MmProjection = stage1.as_ref();
    assert_eq!(
        projection.foreign_mm_binding().stage1_root(),
        Gpa(0x4000),
        "the projection publishes the stage-1 root its mm backend was built on"
    );
    assert_eq!(stage1.binding(), binding);

    let backend = Arc::new(TestMmBackend::new(binding));
    let bootstrap = RootBootstrap::with_mm_backend(
        4_201,
        ThreadId::synthetic_for_tests(4_201),
        Arc::clone(&backend) as Arc<dyn MmBackend>,
        "public-surface-probe-root".to_owned(),
        Arc::new(NullHostSignalBridge::default()),
    )
    .expect("a caller-supplied mm backend boots a root");
    let (kernel, root): (Arc<Kernel>, KernelContext) =
        Kernel::bootstrap_root(bootstrap).expect("bootstrap the root task");
    backend.bind_inventory(&kernel, root.task().shared().mm().id());

    let root_key: TaskKey = root.task().key();
    let prepared: PreparedFork = kernel
        .reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("a plain fork plan"),
            "public-surface-probe-child".to_owned(),
            None,
        )
        .expect("reserve the fork")
        .prepare_reference(ThreadId::synthetic_for_tests(4_202))
        .expect("prepare the child");
    let published: PublishedFork = prepared.commit().expect("publish the child");
    let child_pid = published.visible_child_id();
    let (child, _vfork) = published.into_parts().expect("start the child");

    assert_ne!(
        child.task().key(),
        root_key,
        "the published child is its own task"
    );
    assert_eq!(child.task().key().id.raw(), child_pid);

    // Reap through the public wait operation: a backend's `on_wait` arm.
    kernel
        .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
        .expect("exit the child");
    let reaped = kernel
        .wait_child(root_key.id, Some(child.task().key().id), WaitMode::Consume)
        .expect("reap the child");
    assert!(
        format!("{reaped:?}").contains("Exited") || format!("{reaped:?}").contains("Reaped"),
        "wait_child reported {reaped:?}"
    );
}

#[test]
fn the_carrier_process_double_is_usable_through_the_trait_from_outside() {
    let (carrier, context) =
        TestCarrierProcess::new(4_303).expect("boot a root on the carrier-process double");
    // Through the TRAIT, not the concrete double: this is the shape a backend
    // implements for its own process handle.
    let handle: &dyn CarrierProcess = &carrier;
    assert_eq!(handle.pid(), 4_303);
    assert_eq!(handle.task_key(), context.task().key());
    assert!(
        handle.kernel_graph().container_count() >= 1,
        "the double's kernel graph carries the root's container"
    );
}
