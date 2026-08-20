use std::sync::Arc;

use carrick_abi::LinuxGuestAbi;
use carrick_hal::ThreadId;
use carrick_hal::threaded::{
    Aarch64TaskCpuStateV1, GuestCpuState, X86_TASK_RESUME_MAGIC, X86_TASK_RESUME_PAYLOAD_LEN,
    X86_TASK_XSAVE_LEN, X86TaskCpuStateV1,
};

use super::objects::{
    BlockedReason, ExecutionFailure, ExecutorId, MigratableTaskState, ThreadExecutionError,
    ThreadExecutionState,
};
use super::{Kernel, RootBootstrap};

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
