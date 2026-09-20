//! VM-free policy composition. No guest instructions or VMM are executed.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use carrick_abi::LinuxCloneFlags;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{CpuAffinity, GuestCpuId, SchedulingPolicy, ThreadId};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::scheduler::PreemptionReasons;
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext,
    RootBootstrap, Scheduler,
};

#[derive(Debug, Default)]
struct TestKick {
    binding: parking_lot::Mutex<Option<ExecutorBinding>>,
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
        current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        })
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.binding.lock()
    }
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

fn publish_task(context: &KernelContext, marker: u64) {
    let mm = context.shared().mm().id();
    let state = MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: std::array::from_fn(|index| marker + index as u64),
            pc: marker + 0x1000,
            pstate: marker + 0x2000,
            trap_pc: marker + 0x2100,
            trap_pstate: marker + 0x2200,
            sp_el0: marker + 0x3000,
            elr_el1: marker + 0x3100,
            spsr_el1: marker + 0x3200,
            ttbr0: marker + 0x4000,
            ttbr1: marker + 0x5000,
            tcr: marker + 0x6000,
            sctlr_el1: marker + 0x6100,
            mair_el1: marker + 0x6200,
            vbar_el1: marker + 0x6300,
            cpacr_el1: marker + 0x6400,
            cntkctl_el1: marker + 0x6500,
            tpidr_el1: marker + 0x6600,
            actlr_el1: marker + 0x7000,
            tpidr_el0: marker + 0x8000,
            tpidrro_el0: marker + 0x9000,
            contextidr_el1: marker + 0xa000,
            vregs: std::array::from_fn(|index| marker as u128 + index as u128),
            fpsr: marker as u32,
            fpcr: marker as u32 + 1,
            pending_resume_pc: Some(marker + 0xb000),
            last_syscall_nr: Some(marker),
            last_syscall_orig_x0: marker + 2,
            last_fault_esr: marker + 3,
            last_exit_class: marker,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation: mm.raw(),
            asid_generation: mm.raw(),
        }),
        mm,
        asid_generation: mm.raw(),
    };
    context
        .thread()
        .publish_initial_task_state(state)
        .expect("publish task state");
}

use carrick_abi::{SigBlockMask, SigSet};
use carrick_embed::testing::{AdversarialPolicy, RecordReplay};

// This fixture never exercises signals. Fail immediately if that changes,
// instead of silently supplying incomplete signal semantics.
#[derive(Debug)]
struct NoSignalCalls;
#[allow(clippy::panic)]
impl carrick_hal::HostSignalBridge for NoSignalCalls {
    fn has_unblocked_pending_for(&self, _: i32, _: SigBlockMask) -> bool {
        panic!("unexpected signal call")
    }
    fn take_pending_for(&self, _: i32) -> i32 {
        panic!("unexpected signal call")
    }
    fn take_pending_in_for(&self, _: i32, _: SigSet) -> i32 {
        panic!("unexpected signal call")
    }
    fn publish_pending_for(&self, _: i32, _: i32) {
        panic!("unexpected signal call")
    }
    fn publish_process_signal(&self, _: i32) {
        panic!("unexpected signal call")
    }
    fn last_sender_for(&self, _: i32) -> i32 {
        panic!("unexpected signal call")
    }
    fn raise_for_self(&self, _: i32) {
        panic!("unexpected signal call")
    }
    fn wake_all_waiters(&self) {
        panic!("unexpected signal call")
    }
    fn ensure_host_handler(&self, _: i32) {
        panic!("unexpected signal call")
    }
    fn set_host_ignore(&self, _: i32) {
        panic!("unexpected signal call")
    }
    fn set_host_default(&self, _: i32) {
        panic!("unexpected signal call")
    }
    fn reset_routed_handlers_after_execve(&self, _: SigSet) {
        panic!("unexpected signal call")
    }
    fn xsig_enqueue(&self, _: i32, _: i32, _: i32, _: i32, _: u32, _: i64, _: i32) -> bool {
        panic!("unexpected signal call")
    }
    fn xsig_nudge(&self, _: i32) {
        panic!("unexpected signal call")
    }
    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, i32, u32, i64, i32)> {
        panic!("unexpected signal call")
    }
    fn host_to_linux_signum(&self, _: i32) -> i32 {
        panic!("unexpected signal call")
    }
    fn linux_to_host_signum(&self, _: i32) -> i32 {
        panic!("unexpected signal call")
    }
}

/// Drive real policy placement, queue selection, preemption and host-wait
/// transitions. Pin all tasks to P1 so P0 cannot satisfy this progress proof.
fn handoff(
    policy: Arc<dyn SchedulingPolicy>,
    count: usize,
) -> Vec<carrick_kernel::kernel::objects::ThreadKey> {
    let bootstrap = RootBootstrap::for_one_task_adapter(
        61_000,
        ThreadId::synthetic_for_tests(61_000),
        "policy handoff".into(),
        Arc::new(NoSignalCalls),
    )
    .unwrap();
    let (kernel, root) = Kernel::bootstrap_root(bootstrap).unwrap();
    let cpu = GuestCpuId::new(1);
    root.thread().set_affinity(CpuAffinity::single(cpu));
    publish_task(&root, 100);
    let scheduler = Scheduler::new_with_policy(kernel.clone(), policy);
    let other_cpu = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();
    let owner = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), Some(cpu), false)
        .unwrap();
    let spare = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .unwrap();
    scheduler.make_runnable(root.thread().key()).unwrap();
    let original = scheduler.take(&owner).unwrap();
    let mut expected = Vec::new();
    for index in 0..count {
        let sibling = create_sibling_thread(&kernel, &root, 61_001 + index as i32);
        sibling.thread().set_affinity(CpuAffinity::single(cpu));
        publish_task(&sibling, 200 + index as u64);
        expected.push(sibling.thread().key());
        scheduler.make_runnable(sibling.thread().key()).unwrap();
    }
    let wait = scheduler.begin_host_wait(&original, &owner).unwrap();
    assert!(wait.is_active());
    assert_eq!(owner.bound_cpu(), None);
    assert_eq!(scheduler.queued_len(), count);
    let mut order = Vec::new();
    for _ in 0..count {
        let running = scheduler.take(&spare).unwrap();
        let running_cpu = running.guest_cpu();
        let key = running.thread_key();
        let current = scheduler.binding_for_thread(key);
        let census = scheduler.host_wait_census();
        // Settle before asserting: a fixture failure must not strand the
        // returning original behind a dropped, still-running spare claim.
        scheduler.settle_exited(running).unwrap();
        assert_eq!(running_cpu, cpu);
        assert_eq!(current.as_ref().map(|b| b.thread()), Some(key));
        assert_eq!(current.as_ref().map(|b| b.executor()), Some(spare.id()));
        let census = census.unwrap();
        assert_eq!(census.slots.len(), 1);
        let slot = census
            .slots
            .iter()
            .find(|slot| slot.owner == Some(spare.id()))
            .unwrap();
        assert_eq!(slot.waiters.len(), 1);
        assert_eq!(census.entered, 1);
        assert_eq!(census.resumed, 0);
        order.push(key);
    }
    let mut observed = order.clone();
    observed.sort();
    expected.sort();
    assert_eq!(observed, expected, "every exact claim completes once");
    scheduler.end_host_wait(&original, &owner, wait).unwrap();
    assert_eq!(owner.bound_cpu(), Some(cpu));
    assert_eq!(spare.bound_cpu(), None);
    let census = scheduler.host_wait_census().unwrap();
    assert_eq!((census.entered, census.resumed), (1, 1));
    assert!(census.slots.iter().all(|slot| slot.waiters.is_empty()));
    scheduler.settle_exited(original).unwrap();
    scheduler.close();
    scheduler.wait_closed();
    scheduler.unregister_executor(&spare).unwrap();
    scheduler.unregister_executor(&owner).unwrap();
    scheduler.unregister_executor(&other_cpu).unwrap();
    order
}

#[test]
fn adversarial_policy_preserves_pinned_handoff_ownership() {
    for count in [1, 8, 32] {
        let policy = Arc::new(AdversarialPolicy::new(2, 0x5003));
        handoff(policy.clone(), count);
        assert!(policy.decisions() >= (count * 2) as u64);
    }
}

#[test]
fn recorded_adversarial_handoff_replays_without_fallback() {
    for count in [1, 8, 32] {
        let recording = Arc::new(RecordReplay::recording(Arc::new(AdversarialPolicy::new(
            2, 0x5003,
        ))));
        let expected = handoff(recording.clone(), count);
        let decisions = recording.recorded();
        assert!(!decisions.is_empty());
        let fallback = Arc::new(AdversarialPolicy::new(2, 0xdead));
        let replay = Arc::new(RecordReplay::replaying(fallback.clone(), decisions));
        assert_eq!(handoff(replay.clone(), count), expected);
        assert_eq!(replay.divergences(), 0);
        assert_eq!(
            fallback.decisions(),
            0,
            "replay must consume the recording, not silently fall back"
        );
    }
}

#[test]
fn handoff_disarms_fairness_deadline_and_refreshes_budget_on_resume() {
    let bootstrap = RootBootstrap::for_one_task_adapter(
        62_000,
        ThreadId::synthetic_for_tests(62_000),
        "preemption handoff".into(),
        Arc::new(NoSignalCalls),
    )
    .unwrap();
    let (kernel, root) = Kernel::bootstrap_root(bootstrap).unwrap();
    let cpu = GuestCpuId::new(0);
    root.thread().set_affinity(CpuAffinity::single(cpu));
    publish_task(&root, 100);

    let scheduler = Scheduler::new(kernel.clone());
    let owner = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), Some(cpu), false)
        .unwrap();
    let spare = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .unwrap();

    scheduler.make_runnable(root.thread().key()).unwrap();
    let original = scheduler.take(&owner).unwrap();

    // Owner has an active residency
    let res = scheduler.binding_residency(owner.id()).expect("residency");
    assert_eq!(res.cpu, cpu);
    assert_eq!(res.reasons, PreemptionReasons::empty());

    // Sibling is queued and creates contention
    let sibling = create_sibling_thread(&kernel, &root, 62_001);
    sibling.thread().set_affinity(CpuAffinity::single(cpu));
    publish_task(&sibling, 200);
    scheduler.make_runnable(sibling.thread().key()).unwrap();

    // Owner enters host wait: fairness is cancelled, residency suspended
    let wait = scheduler.begin_host_wait(&original, &owner).unwrap();
    assert!(wait.is_active());
    assert!(scheduler.binding_residency(owner.id()).is_none());
    assert!(!scheduler.has_deadline(owner.id()));

    // Spare claims the slot and runs the sibling with independent residency
    let running = scheduler.take(&spare).unwrap();
    assert_eq!(running.guest_cpu(), cpu);
    let spare_res = scheduler
        .binding_residency(spare.id())
        .expect("spare residency");
    assert_eq!(spare_res.cpu, cpu);
    assert_eq!(spare_res.thread, sibling.thread().key());
    scheduler.settle_exited(running).unwrap();

    // End host wait: original reacquires slot, receives fresh residency & budget
    scheduler.end_host_wait(&original, &owner, wait).unwrap();
    let restored = scheduler
        .binding_residency(owner.id())
        .expect("restored residency");
    assert_eq!(restored.cpu, cpu);
    assert!(
        !restored
            .reasons
            .contains(PreemptionReasons::HOST_WAIT_RETURN)
    );
    assert!(!scheduler.should_preempt(&original));

    scheduler.settle_exited(original).unwrap();
    scheduler.close();
    scheduler.wait_closed();
    scheduler.unregister_executor(&spare).unwrap();
    scheduler.unregister_executor(&owner).unwrap();
}

#[test]
fn handoff_preserves_mandatory_control_reasons_through_resume() {
    let bootstrap = RootBootstrap::for_one_task_adapter(
        63_000,
        ThreadId::synthetic_for_tests(63_000),
        "control reason handoff".into(),
        Arc::new(NoSignalCalls),
    )
    .unwrap();
    let (kernel, root) = Kernel::bootstrap_root(bootstrap).unwrap();
    let cpu = GuestCpuId::new(0);
    root.thread().set_affinity(CpuAffinity::single(cpu));
    publish_task(&root, 100);

    let scheduler = Scheduler::new(kernel.clone());
    let owner = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), Some(cpu), false)
        .unwrap();

    scheduler.make_runnable(root.thread().key()).unwrap();
    let original = scheduler.take(&owner).unwrap();

    // Set both mandatory control reasons and fairness
    assert!(scheduler.set_preemption_reason(
        owner.id(),
        PreemptionReasons::SIGNAL | PreemptionReasons::CONTROL | PreemptionReasons::FAIRNESS,
    ));

    // Begin host wait
    let wait = scheduler.begin_host_wait(&original, &owner).unwrap();
    assert!(scheduler.binding_residency(owner.id()).is_none());

    // End host wait
    scheduler.end_host_wait(&original, &owner, wait).unwrap();

    let restored = scheduler
        .binding_residency(owner.id())
        .expect("restored residency");
    // Mandatory reasons survive. Fairness was cancelled and the completed
    // handoff itself does not manufacture a new preemption reason.
    assert!(restored.reasons.contains(PreemptionReasons::SIGNAL));
    assert!(restored.reasons.contains(PreemptionReasons::CONTROL));
    assert!(
        !restored
            .reasons
            .contains(PreemptionReasons::HOST_WAIT_RETURN)
    );
    assert!(!restored.reasons.contains(PreemptionReasons::FAIRNESS));
    assert!(scheduler.should_preempt(&original));

    scheduler.settle_exited(original).unwrap();
    scheduler.close();
    scheduler.wait_closed();
    scheduler.unregister_executor(&owner).unwrap();
}
