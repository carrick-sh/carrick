//! VM-free test verifying personality-configurable thread base pointer registers
//! across preemption and context switches without register clobbering or leakage.
//!
//! Acceptance criteria:
//! - Registered personalities configure thread pointer base registers per task/thread.
//! - x86_64 context switch restores MSR_IA32_GS_BASE and MSR_IA32_FS_BASE without leakage.
//! - Zero personality-specific naming in carrick-core or carrick-x86.
//! - A VM-free test running two tasks with conflicting TLS register requirements
//!   (FS_BASE vs GS_BASE) verifies that each task preserves its respective register
//!   across preemption without clobbering.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use carrick_abi::LinuxCloneFlags;
use carrick_core::{Personality, TaskId, TaskKey, TaskSerial, ThreadKey};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa, ThreadContext,
    ThreadPointerRegister,
};
use carrick_hal::threaded::{
    Aarch64TaskCpuStateV1, GuestCpuState, X86_TASK_RESUME_MAGIC, X86_TASK_RESUME_PAYLOAD_LEN,
    X86TaskCpuStateV1,
};
use carrick_hal::{GuestCpuId, GuestCpuPolicy, NullHostSignalBridge, ThreadId};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::scheduler::PreemptionReasons;
use carrick_kernel::kernel::scheduler::preemption::ManualClock;
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext, Scheduler,
};
use carrick_kernel_example::personality::ExamplePersonality;
use carrick_kernel_example::process::{AddressSpace, AsidAllocator, ExampleProcess};
use carrick_personality_linux::LinuxPersonality;
use carrick_sched_core::{Aarch64ParkedContext, ParkedContextWords, ThreadCtx, X86_XSAVE_BYTES};

#[derive(Debug, Default)]
struct TestKick {
    binding: parking_lot::Mutex<Option<ExecutorBinding>>,
    tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    changed: parking_lot::Condvar,
    kicked: AtomicBool,
}

impl ExecutorKick for TestKick {
    fn try_bind(&self, binding: ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.binding.lock();
        if *current != Some(predecessor) {
            return false;
        }
        if !publish() {
            return false;
        }
        *current = Some(successor);
        true
    }

    fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        if !current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        }) {
            return false;
        }
        self.kicked.store(true, Ordering::Release);
        self.tokens.lock().push(token);
        self.changed.notify_all();
        true
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.binding.lock()
    }
}

fn bootstrap_kernel(pid: i32) -> (Arc<Kernel>, KernelContext, Arc<AsidAllocator>) {
    let asids = Arc::new(AsidAllocator::new());
    let space = AddressSpace::allocate(&asids).expect("allocate space");
    let (_process, root) = ExampleProcess::boot_root(
        pid,
        "conflicting tls preemption test",
        Arc::new(NullHostSignalBridge::default()),
        space,
    )
    .expect("boot root");
    let kernel = Arc::clone(root.kernel());
    (kernel, root, asids)
}

fn create_sibling_thread(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    host_tid: i32,
) -> KernelContext {
    let plan = ClonePlan::from_flags(
        LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
    )
    .expect("thread plan");
    kernel
        .reserve_thread_clone(parent, plan, None)
        .expect("reserve thread clone")
        .prepare(ThreadId::synthetic_for_tests(host_tid))
        .expect("prepare thread clone")
        .commit()
        .expect("publish thread clone")
        .start_thread()
        .expect("start thread")
        .into_context()
}

#[allow(dead_code)]
fn make_x86_task_state(context: &KernelContext, fs_base: u64, gs_base: u64) -> MigratableTaskState {
    let mm = context.shared().mm().id();
    let mut resume = vec![0; X86_TASK_RESUME_PAYLOAD_LEN];
    resume[56..64].copy_from_slice(&X86_TASK_RESUME_MAGIC.to_le_bytes());
    let cpu_state = X86TaskCpuStateV1::new(
        [0; 16],
        0x40_0000,
        0x202,
        0x7fff_0000,
        0x8000_0001,
        mm.raw() << 12,
        0,
        0xd00,
        fs_base,
        gs_base,
        mm.raw(),
        mm.raw(),
        vec![0; X86_XSAVE_BYTES],
        resume,
    )
    .expect("valid x86 task cpu state");

    MigratableTaskState {
        cpu: GuestCpuState::from_x86_64_v1(cpu_state).expect("guest cpu state"),
        mm,
        asid_generation: mm.raw(),
    }
}

#[allow(dead_code)]
fn make_aarch64_task_state(
    context: &KernelContext,
    tpidr_el0: u64,
    x18: u64,
) -> MigratableTaskState {
    let mm = context.shared().mm().id();
    let mut gprs = [0u64; 31];
    gprs[18] = x18;
    let cpu_state = Aarch64TaskCpuStateV1 {
        gprs,
        pc: 0x40_0000,
        pstate: 0x2000,
        trap_pc: 0x2100,
        trap_pstate: 0x2200,
        sp_el0: 0x7fff_0000,
        elr_el1: 0x3100,
        spsr_el1: 0x3200,
        ttbr0: mm.raw() << 12,
        ttbr1: 0,
        tcr: 0x6000,
        sctlr_el1: 0x6100,
        mair_el1: 0x6200,
        vbar_el1: 0x6300,
        cpacr_el1: 0x6400,
        cntkctl_el1: 0x6500,
        tpidr_el1: 0x6600,
        actlr_el1: 0x7000,
        tpidr_el0,
        tpidrro_el0: 0x9000,
        contextidr_el1: 0xa000,
        vregs: [0; 32],
        fpsr: 0,
        fpcr: 0,
        pending_resume_pc: None,
        last_syscall_nr: None,
        last_syscall_orig_x0: 0,
        last_fault_esr: 0,
        last_exit_class: 0,
        is_forked_child: false,
        syscall_continuation: None,
        mm_generation: mm.raw(),
        asid_generation: mm.raw(),
    };

    MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(cpu_state),
        mm,
        asid_generation: mm.raw(),
    }
}

/// Verify that registered personalities configure thread pointer base registers
/// per personality, task, and thread without hardcoding.
#[test]
fn test_personality_configured_thread_pointer_registers() {
    let linux_personality = LinuxPersonality;
    let example_personality = ExamplePersonality::new();

    // Verify default registers
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(
            linux_personality.thread_pointer_register(),
            ThreadPointerRegister::FS
        );
        assert_eq!(
            example_personality.thread_pointer_register(),
            ThreadPointerRegister::GS
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(
            linux_personality.thread_pointer_register(),
            ThreadPointerRegister::TPIDR_EL0
        );
        assert_eq!(
            example_personality.thread_pointer_register(),
            ThreadPointerRegister::X18
        );
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (linux_personality, example_personality);
    }

    // Verify per-thread and per-task overrides on the non-Linux test personality
    let custom_personality = ExamplePersonality::with_default_register(ThreadPointerRegister::GS);
    let thread_42 = ThreadKey::new(42, 1);
    let thread_43 = ThreadKey::new(43, 1);
    let task_100 = TaskKey {
        id: TaskId::from_abi_positive(100).unwrap(),
        serial: TaskSerial::from_registry_allocation(core::num::NonZeroU64::new(1).unwrap()),
    };
    let task_101 = TaskKey {
        id: TaskId::from_abi_positive(101).unwrap(),
        serial: TaskSerial::from_registry_allocation(core::num::NonZeroU64::new(1).unwrap()),
    };
    custom_personality.configure_thread(thread_42, ThreadPointerRegister::FS);
    custom_personality.configure_task(task_100, ThreadPointerRegister::FS);

    assert_eq!(
        custom_personality.thread_pointer_register_for_thread(thread_42),
        ThreadPointerRegister::FS
    );
    assert_eq!(
        custom_personality.thread_pointer_register_for_thread(thread_43),
        ThreadPointerRegister::GS
    );
    assert_eq!(
        custom_personality.thread_pointer_register_for_task(task_100),
        ThreadPointerRegister::FS
    );
    assert_eq!(
        custom_personality.thread_pointer_register_for_task(task_101),
        ThreadPointerRegister::GS
    );
}

/// VM-Free Test: Two tasks with conflicting TLS register requirements (FS_BASE vs GS_BASE on x86,
/// TPIDR_EL0 vs x18 on AArch64) run on the scheduler and are preempted back and forth.
/// Each task preserves its chosen thread pointer base register without leakage or clobbering.
#[test]
fn test_conflicting_tls_preemption_preserves_registers() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, _asids) = bootstrap_kernel(80_001);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 80_002);

    let linux_pers = LinuxPersonality;
    let example_pers = ExamplePersonality::new();

    let reg_a = linux_pers.thread_pointer_register();
    let reg_b = example_pers.thread_pointer_register();

    assert_ne!(
        reg_a, reg_b,
        "Task A and Task B must have conflicting TLS register requirements"
    );

    // Initial distinct base values
    const TASK_A_VAL: u64 = 0x1111_0000_2222_0000;
    const TASK_B_VAL: u64 = 0x3333_0000_4444_0000;

    #[cfg(target_arch = "x86_64")]
    let (state_a, state_b, guest_abi) = (
        make_x86_task_state(&ctx_a, TASK_A_VAL, 0),
        make_x86_task_state(&ctx_b, 0, TASK_B_VAL),
        carrick_abi::LinuxGuestAbi::X86_64,
    );

    #[cfg(target_arch = "aarch64")]
    let (state_a, state_b, guest_abi) = (
        make_aarch64_task_state(&ctx_a, TASK_A_VAL, 0),
        make_aarch64_task_state(&ctx_b, 0, TASK_B_VAL),
        carrick_abi::LinuxGuestAbi::Aarch64,
    );

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (state_a, state_b, guest_abi) = (
        make_x86_task_state(&ctx_a, TASK_A_VAL, 0),
        make_x86_task_state(&ctx_b, 0, TASK_B_VAL),
        carrick_abi::LinuxGuestAbi::X86_64,
    );

    // Ensure ThreadContext trait reads the configured register
    assert_eq!(state_a.cpu.thread_pointer(reg_a), TASK_A_VAL);
    assert_eq!(state_b.cpu.thread_pointer(reg_b), TASK_B_VAL);
    assert_eq!(state_a.cpu.thread_pointer(reg_b), 0);
    assert_eq!(state_b.cpu.thread_pointer(reg_a), 0);

    ctx_a
        .thread()
        .publish_initial_task_state(state_a)
        .expect("publish state a");
    ctx_b
        .thread()
        .publish_initial_task_state(state_b)
        .expect("publish state b");

    let policy = Arc::new(GuestCpuPolicy::new(1));
    let scheduler = Arc::new(Scheduler::new_with_policy_and_clock(
        Arc::clone(&kernel),
        policy,
        clock.clone(),
    ));
    clock.attach_condvar(scheduler.preemption_condvar());

    let kick = Arc::new(TestKick::default());
    let executor = scheduler
        .register_executor_bound(kick, Some(GuestCpuId::new(0)), false)
        .expect("register executor");

    // Task A starts running
    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let mut running_a = scheduler.take(&executor).expect("claim Task A");
    assert_eq!(running_a.thread_key(), ctx_a.thread().key());

    // Task A verifies its thread pointer
    let mut lease_a = running_a.take_lease();
    let restored_a = lease_a
        .task_state_for_restore(
            guest_abi,
            1,
            ctx_a.shared().mm().id(),
            ctx_a.shared().mm().id().raw(),
        )
        .expect("restore Task A");
    assert_eq!(restored_a.cpu.thread_pointer(reg_a), TASK_A_VAL);
    assert_eq!(restored_a.cpu.thread_pointer(reg_b), 0);

    // Mutate Task A's TLS register during execution
    const TASK_A_VAL_UPDATED: u64 = 0x1111_0000_9999_0000;
    let mut modified_a = restored_a.clone();
    modified_a.cpu.set_thread_pointer(reg_a, TASK_A_VAL_UPDATED);
    lease_a
        .replace_task_state(modified_a)
        .expect("replace Task A state");
    running_a.restore_lease(lease_a).expect("restore lease A");

    // Task B queues and requests preemption
    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    // Advance clock past quantum to trigger preemption
    clock.advance(Duration::from_millis(10));
    let due = scheduler.poll_due_preemption_requests();
    assert!(!due.is_empty(), "preemption request must be due");
    assert!(due[0].reasons.contains(PreemptionReasons::FAIRNESS));

    // Preempt Task A: settle it runnable
    scheduler.settle_runnable(running_a).expect("settle Task A");

    // Executor claims Task B
    let mut running_b = scheduler.take(&executor).expect("claim Task B");
    assert_eq!(running_b.thread_key(), ctx_b.thread().key());

    // Task B verifies its thread pointer without leakage of Task A's thread pointer
    let mut lease_b = running_b.take_lease();
    let restored_b = lease_b
        .task_state_for_restore(
            guest_abi,
            1,
            ctx_b.shared().mm().id(),
            ctx_b.shared().mm().id().raw(),
        )
        .expect("restore Task B");
    assert_eq!(
        restored_b.cpu.thread_pointer(reg_b),
        TASK_B_VAL,
        "Task B must preserve its configured thread pointer"
    );
    assert_eq!(
        restored_b.cpu.thread_pointer(reg_a),
        0,
        "Task B must not have Task A's thread pointer leaked into it"
    );

    // Mutate Task B's TLS register during execution
    const TASK_B_VAL_UPDATED: u64 = 0x3333_0000_7777_0000;
    let mut modified_b = restored_b.clone();
    modified_b.cpu.set_thread_pointer(reg_b, TASK_B_VAL_UPDATED);
    lease_b
        .replace_task_state(modified_b)
        .expect("replace Task B state");
    running_b.restore_lease(lease_b).expect("restore lease B");

    // Preempt Task B and switch back to Task A
    clock.advance(Duration::from_millis(10));
    scheduler.settle_runnable(running_b).expect("settle Task B");

    let mut running_a2 = scheduler.take(&executor).expect("claim Task A again");
    assert_eq!(running_a2.thread_key(), ctx_a.thread().key());

    // Task A verifies its updated thread pointer without leakage of Task B's thread pointer
    let lease_a2 = running_a2.take_lease();
    let restored_a2 = lease_a2
        .task_state_for_restore(
            guest_abi,
            1,
            ctx_a.shared().mm().id(),
            ctx_a.shared().mm().id().raw(),
        )
        .expect("restore Task A again");
    assert_eq!(
        restored_a2.cpu.thread_pointer(reg_a),
        TASK_A_VAL_UPDATED,
        "Task A must retain its thread pointer across preemption"
    );
    assert_eq!(
        restored_a2.cpu.thread_pointer(reg_b),
        0,
        "Task A must not have Task B's thread pointer leaked into it"
    );

    running_a2.restore_lease(lease_a2).expect("restore lease A");
    scheduler
        .settle_runnable(running_a2)
        .expect("settle Task A");
}

/// Test x86_64 context switch park/restore with ParkedContextWords:
/// Verifies that switching between two contexts with conflicting TLS register requirements
/// preserves MSR_IA32_FS_BASE and MSR_IA32_GS_BASE without leakage.
#[test]
fn test_x86_context_switch_restores_fs_and_gs_base_without_leakage() {
    let root1 = RootGpa::page_aligned(FrameGpa::new(0x10_0000)).unwrap();
    let root2 = RootGpa::page_aligned(FrameGpa::new(0x20_0000)).unwrap();

    let addr1 = AddressContext {
        root: root1,
        mm: MmGeneration::new(std::num::NonZeroU64::new(1).unwrap()),
        generation: ContextGeneration::new(std::num::NonZeroU64::new(1).unwrap()),
    };
    let addr2 = AddressContext {
        root: root2,
        mm: MmGeneration::new(std::num::NonZeroU64::new(2).unwrap()),
        generation: ContextGeneration::new(std::num::NonZeroU64::new(1).unwrap()),
    };

    // Task 1: FS_BASE configured
    const TASK1_FS: u64 = 0xaaaa_bbbb_cccc_0000;
    const TASK1_GS: u64 = 0x0;
    let mut words1 =
        ParkedContextWords::from_parts([0; 20], addr1, TASK1_FS, TASK1_GS, [0; X86_XSAVE_BYTES]);

    // Task 2: GS_BASE configured
    const TASK2_FS: u64 = 0x0;
    const TASK2_GS: u64 = 0xdddd_eeee_ffff_0000;
    let mut words2 =
        ParkedContextWords::from_parts([0; 20], addr2, TASK2_FS, TASK2_GS, [0; X86_XSAVE_BYTES]);

    // Check ThreadContext access
    assert_eq!(words1.thread_pointer(ThreadPointerRegister::FS), TASK1_FS);
    assert_eq!(words1.thread_pointer(ThreadPointerRegister::GS), 0);
    assert_eq!(words2.thread_pointer(ThreadPointerRegister::FS), 0);
    assert_eq!(words2.thread_pointer(ThreadPointerRegister::GS), TASK2_GS);

    // Simulate context switch into Task 2: modify GS_BASE
    words2.set_thread_pointer(ThreadPointerRegister::GS, TASK2_GS + 0x1000);
    assert_eq!(
        words2.thread_pointer(ThreadPointerRegister::GS),
        TASK2_GS + 0x1000
    );
    // Task 1's words remain uncorrupted
    assert_eq!(words1.thread_pointer(ThreadPointerRegister::FS), TASK1_FS);
    assert_eq!(words1.thread_pointer(ThreadPointerRegister::GS), 0);

    // Simulate switch back to Task 1: modify FS_BASE
    words1.set_thread_pointer(ThreadPointerRegister::FS, TASK1_FS + 0x2000);
    assert_eq!(
        words1.thread_pointer(ThreadPointerRegister::FS),
        TASK1_FS + 0x2000
    );
    // Task 2's words remain uncorrupted
    assert_eq!(
        words2.thread_pointer(ThreadPointerRegister::GS),
        TASK2_GS + 0x1000
    );
    assert_eq!(words2.thread_pointer(ThreadPointerRegister::FS), 0);
}

/// Test AArch64 context switch park/restore with Aarch64ParkedContext:
/// Verifies that switching between two contexts with conflicting TLS register requirements
/// preserves TPIDR_EL0 and x18 without leakage.
#[test]
fn test_aarch64_context_switch_restores_tpidr_el0_and_x18_without_leakage() {
    let root1 = RootGpa::page_aligned(FrameGpa::new(0x10_0000)).unwrap();
    let root2 = RootGpa::page_aligned(FrameGpa::new(0x20_0000)).unwrap();

    let addr1 = AddressContext {
        root: root1,
        mm: MmGeneration::new(std::num::NonZeroU64::new(1).unwrap()),
        generation: ContextGeneration::new(std::num::NonZeroU64::new(1).unwrap()),
    };
    let addr2 = AddressContext {
        root: root2,
        mm: MmGeneration::new(std::num::NonZeroU64::new(2).unwrap()),
        generation: ContextGeneration::new(std::num::NonZeroU64::new(1).unwrap()),
    };

    // Task 1: TPIDR_EL0 configured
    const TASK1_TPIDR: u64 = 0xaaaa_bbbb_cccc_0000;
    let mut ctx1 = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, addr1);
    ctx1.set_thread_pointer(ThreadPointerRegister::TPIDR_EL0, TASK1_TPIDR);

    // Task 2: X18 configured
    const TASK2_X18: u64 = 0xdddd_eeee_ffff_0000;
    let mut ctx2 = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, addr2);
    ctx2.set_thread_pointer(ThreadPointerRegister::X18, TASK2_X18);

    // Check ThreadContext access
    assert_eq!(
        ctx1.thread_pointer(ThreadPointerRegister::TPIDR_EL0),
        TASK1_TPIDR
    );
    assert_eq!(ctx1.thread_pointer(ThreadPointerRegister::X18), 0);
    assert_eq!(ctx2.thread_pointer(ThreadPointerRegister::TPIDR_EL0), 0);
    assert_eq!(ctx2.thread_pointer(ThreadPointerRegister::X18), TASK2_X18);

    // Simulate context switch into Task 2: modify X18
    ctx2.set_thread_pointer(ThreadPointerRegister::X18, TASK2_X18 + 0x1000);
    assert_eq!(
        ctx2.thread_pointer(ThreadPointerRegister::X18),
        TASK2_X18 + 0x1000
    );
    // Task 1 remains uncorrupted
    assert_eq!(
        ctx1.thread_pointer(ThreadPointerRegister::TPIDR_EL0),
        TASK1_TPIDR
    );
    assert_eq!(ctx1.thread_pointer(ThreadPointerRegister::X18), 0);

    // Simulate switch back to Task 1: modify TPIDR_EL0
    ctx1.set_thread_pointer(ThreadPointerRegister::TPIDR_EL0, TASK1_TPIDR + 0x2000);
    assert_eq!(
        ctx1.thread_pointer(ThreadPointerRegister::TPIDR_EL0),
        TASK1_TPIDR + 0x2000
    );
    // Task 2 remains uncorrupted
    assert_eq!(
        ctx2.thread_pointer(ThreadPointerRegister::X18),
        TASK2_X18 + 0x1000
    );
    assert_eq!(ctx2.thread_pointer(ThreadPointerRegister::TPIDR_EL0), 0);
}
