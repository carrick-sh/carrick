//! Scheduling policy contract for Carrick's HVPatch kernel.
//!
//! The split is deliberate and load-bearing: *mechanism* (exact-generation
//! claims, `WakeAdmission`, settlement, executor audits, close/drain
//! observation counting) stays in `carrick-runtime`'s scheduler and is not
//! pluggable, because no policy may express a wrong invariant. *Policy* —
//! "which guest CPU, which task next" — is this trait. It never sees host
//! threads, HVF vCPUs, execution generations or leases.

use std::cmp;
use std::fmt;

/// The number of guest CPUs (`P`s) the run queue can address.
///
/// The run queue keeps a fixed-width per-CPU idle/load lane per `P`, so the
/// count of scheduler `P`s is clamped here. This does NOT clamp the
/// guest-visible `nproc`/`sched_getaffinity` surface, which is
/// `host_facts::logical_cpu_count()`; on every host Carrick runs on today the
/// exposed count is far below this bound and the two are identical.
pub const MAX_GUEST_CPUS: usize = 64;

/// Strongly-typed guest CPU identifier (0-indexed). This is the identity the
/// guest observes through `sched_getcpu`, `getcpu(2)` and `/proc/<pid>/stat`
/// field 39, not a host core number.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GuestCpuId(u32);

impl GuestCpuId {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for GuestCpuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpu#{}", self.0)
    }
}

/// Policy-facing task identity. This is the kernel task/thread serial, which
/// is never reused, so a policy may key its own state on it without ever
/// naming a generation or a host thread.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskKey(u64);

impl TaskKey {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TaskKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task#{}", self.0)
    }
}

const AFFINITY_WORDS: usize = MAX_GUEST_CPUS.div_ceil(64);

/// Which guest CPUs a task may run on.
///
/// Deliberately inline and `Copy`: a placement decision is taken on every
/// wake, and a heap allocation there is a per-wake cost the design exists to
/// remove.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuAffinity {
    words: [u64; AFFINITY_WORDS],
}

impl CpuAffinity {
    /// Every CPU below `ncpu` allowed (`ncpu` is clamped to [`MAX_GUEST_CPUS`]).
    pub fn all(ncpu: usize) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        for cpu in 0..ncpu.min(MAX_GUEST_CPUS) {
            words[cpu / 64] |= 1u64 << (cpu % 64);
        }
        Self { words }
    }

    /// Exactly one CPU allowed.
    pub fn single(cpu: GuestCpuId) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        let idx = cpu.as_usize();
        if idx < MAX_GUEST_CPUS {
            words[idx / 64] |= 1u64 << (idx % 64);
        }
        Self { words }
    }

    /// The low `MAX_GUEST_CPUS` bits of a guest `cpu_set_t` word mask.
    pub fn from_words(mask: &[u64]) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        for (slot, word) in words.iter_mut().zip(mask.iter()) {
            *slot = *word;
        }
        Self { words }
    }

    pub const fn words(&self) -> &[u64] {
        &self.words
    }

    pub fn is_allowed(&self, cpu: GuestCpuId) -> bool {
        let idx = cpu.as_usize();
        if idx >= MAX_GUEST_CPUS {
            return false;
        }
        self.words[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    pub fn count_allowed(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    pub fn intersect(&self, other: &Self) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        for (i, slot) in words.iter_mut().enumerate() {
            *slot = self.words[i] & other.words[i];
        }
        Self { words }
    }

    /// The lowest allowed CPU below `ncpu`, if any.
    pub fn first_allowed(&self, ncpu: usize) -> Option<GuestCpuId> {
        (0..ncpu.min(MAX_GUEST_CPUS))
            .map(|i| GuestCpuId::new(i as u32))
            .find(|cpu| self.is_allowed(*cpu))
    }
}

impl Default for CpuAffinity {
    fn default() -> Self {
        Self::all(MAX_GUEST_CPUS)
    }
}

/// What the mechanism knows about one guest CPU when it asks a policy where a
/// task should run.
///
/// The load-bearing field is `idle`. Queue depth alone cannot tell "one
/// executor running and two parked" from "three executors running": both read
/// `queued == 0`, and a policy that trusts that will keep piling wakes onto a
/// CPU whose every `M` is busy while another CPU's `M`s sit parked. Executor
/// availability is the placement signal; the queue is only the backlog behind
/// it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuLoad {
    /// Rows queued on this CPU that no executor has claimed yet.
    pub queued: usize,
    /// Executors bound to this CPU that are parked, or have announced
    /// idleness and are about to park. Either way they will take a row that
    /// arrives now.
    pub idle: usize,
    /// Executors bound to this CPU at all. `0` means the CPU is OFFLINE:
    /// nothing runs there, so a row placed on it waits for a thief.
    pub bound: usize,
}

impl CpuLoad {
    /// An `M` is bound here, so a row placed here will eventually run.
    pub fn is_online(&self) -> bool {
        self.bound > 0
    }

    /// An executor here takes a row the moment it is queued.
    pub fn has_free_executor(&self) -> bool {
        self.idle > 0
    }

    /// Executors here that are currently running a task.
    pub fn running(&self) -> usize {
        self.bound.saturating_sub(self.idle)
    }

    /// Everything this CPU owes: what its executors are running plus what is
    /// queued behind them.
    pub fn runnable(&self) -> usize {
        self.running().saturating_add(self.queued)
    }

    /// A CPU that will start a newly placed row immediately: an idle executor
    /// and no backlog ahead of it.
    fn is_immediately_free(&self) -> bool {
        self.is_online() && self.has_free_executor() && self.queued == 0
    }

    /// Placement preference, best first. Three tiers, because comparing a
    /// ratio across tiers is meaningless:
    ///
    /// 1. immediately free — an idle executor and no backlog (most idle wins);
    /// 2. online — ordered by `runnable / bound`, so a CPU carrying three
    ///    `M`s is not judged against one carrying two by raw counts;
    /// 3. offline — nothing runs there.
    pub fn placement_order(&self, other: &Self) -> cmp::Ordering {
        match (self.is_immediately_free(), other.is_immediately_free()) {
            (true, false) => return cmp::Ordering::Less,
            (false, true) => return cmp::Ordering::Greater,
            (true, true) => return other.idle.cmp(&self.idle),
            (false, false) => {}
        }
        match (self.is_online(), other.is_online()) {
            (true, false) => return cmp::Ordering::Less,
            (false, true) => return cmp::Ordering::Greater,
            (false, false) => return cmp::Ordering::Equal,
            (true, true) => {}
        }
        // `self.runnable / self.bound` vs `other.runnable / other.bound`,
        // cross-multiplied so the comparison stays in integers. Both `bound`
        // are non-zero here.
        let lhs = (self.runnable() as u128) * (other.bound as u128);
        let rhs = (other.runnable() as u128) * (self.bound as u128);
        lhs.cmp(&rhs)
    }
}

/// Everything a policy is told about a task that is becoming runnable.
#[derive(Clone, Copy, Debug)]
pub struct TaskPlacement<'a> {
    pub task: TaskKey,
    /// The CPU this task last ran on, if it has run.
    pub last_cpu: Option<GuestCpuId>,
    pub affinity: CpuAffinity,
    /// Executor availability and backlog per CPU, indexed by [`GuestCpuId`].
    pub cpus: &'a [CpuLoad],
}

impl TaskPlacement<'_> {
    pub fn load_of(&self, cpu: GuestCpuId) -> CpuLoad {
        self.cpus.get(cpu.as_usize()).copied().unwrap_or_default()
    }
}

/// The answer [`SchedulingPolicy::on_tick`] gives about the running task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreemptOrContinue {
    Preempt,
    Continue,
}

/// A view of one guest CPU's queue, handed to a policy so `pick_next` and
/// `steal` can choose without the policy holding any scheduler lock.
#[derive(Clone, Copy, Debug)]
pub struct CpuQueueView<'a> {
    pub cpu: GuestCpuId,
    /// Tasks queued on `cpu`, in FIFO order.
    pub queued: &'a [TaskKey],
}

/// Pluggable scheduling policy: "which guest CPU, which task next".
///
/// An embedder installs one with `ContainerBuilder::scheduler`. Every method
/// has a default that reproduces the mechanism's own FIFO/longest-queue
/// behaviour, so a policy only overrides what it wants to decide.
pub trait SchedulingPolicy: Send + Sync + fmt::Debug {
    /// Number of guest CPUs this policy schedules. Clamped by the mechanism to
    /// `1..=MAX_GUEST_CPUS`; it is also the guest's `sched_getcpu` range.
    fn cpu_count(&self) -> usize;

    /// Place a task that is becoming runnable.
    fn select_cpu(&self, placement: &TaskPlacement<'_>) -> GuestCpuId;

    /// Whether [`Self::pick_next`] and [`Self::steal`] should be consulted.
    ///
    /// The default is `false` so the mechanism never materializes a queue view
    /// on the claim hot path. A policy that overrides either method MUST
    /// override this to `true` or it will never be asked.
    fn inspects_queues(&self) -> bool {
        false
    }

    /// Choose which queued task `cpu` runs next. `None` = the mechanism's FIFO
    /// head. A returned task that is not in `view.queued` is ignored.
    fn pick_next(&self, _view: &CpuQueueView<'_>) -> Option<TaskKey> {
        None
    }

    /// Choose a task for idle `cpu` to steal. `None` = the mechanism's
    /// longest-queue scan. Affinity is always re-checked by the mechanism.
    fn steal(
        &self,
        _cpu: GuestCpuId,
        _victims: &[CpuQueueView<'_>],
    ) -> Option<(GuestCpuId, TaskKey)> {
        None
    }

    /// Periodic tick: should the task currently on `cpu` be preempted?
    fn on_tick(&self, _cpu: GuestCpuId) -> PreemptOrContinue {
        PreemptOrContinue::Continue
    }

    fn on_runnable(&self, _task: TaskKey, _cpu: GuestCpuId) {}

    fn on_block(&self, _task: TaskKey, _cpu: GuestCpuId) {}

    fn on_exit(&self, _task: TaskKey, _cpu: GuestCpuId) {}
}

/// The default policy: per-CPU queues, a `last_cpu` wake that is taken only
/// when an executor there will actually run the task now, and least-loaded
/// placement by executor availability otherwise.
///
/// This is Linux `select_task_rq_fair`'s shape, not Go's: wake to the previous
/// CPU when it is idle (cache-hot and free), otherwise to the CPU with the
/// most spare execution capacity. Round 1 made the sticky decision on queue
/// depth alone and a fork burst serialized behind the parent's CPU.
#[derive(Clone, Copy, Debug)]
pub struct GuestCpuPolicy {
    cpu_count: usize,
    /// How much backlog `last_cpu` may already carry and still win a sticky
    /// wake. A free executor there is required either way; this only says
    /// whether rows may already be queued ahead of the wakee.
    ///
    /// Default `0`: warmth is worth having only when the task starts running
    /// immediately. Raising it trades spread for ASID/TLB reuse.
    sticky_depth: usize,
}

impl GuestCpuPolicy {
    pub fn new(cpu_count: usize) -> Self {
        Self {
            cpu_count: cpu_count.clamp(1, MAX_GUEST_CPUS),
            sticky_depth: 0,
        }
    }

    /// Backlog tolerated on a sticky wake. `0` is the default; the mechanism
    /// exposes this so an ablation can move it without a second policy.
    pub fn with_sticky_depth(mut self, sticky_depth: usize) -> Self {
        self.sticky_depth = sticky_depth;
        self
    }
}

impl SchedulingPolicy for GuestCpuPolicy {
    fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    fn select_cpu(&self, placement: &TaskPlacement<'_>) -> GuestCpuId {
        let ncpu = self.cpu_count;
        let allowed = |cpu: GuestCpuId| cpu.as_usize() < ncpu && placement.affinity.is_allowed(cpu);

        // Sticky wake, but only when `last_cpu` has an executor free to take
        // the task now. `last_cpu` with every `M` running is exactly the
        // serialization this rule exists to avoid: the wakee would sit in a
        // queue while another CPU's executors are parked.
        if let Some(last) = placement.last_cpu
            && allowed(last)
        {
            let load = placement.load_of(last);
            if load.is_online() && load.has_free_executor() && load.queued <= self.sticky_depth {
                return last;
            }
        }

        let mut best: Option<(GuestCpuId, CpuLoad)> = None;
        for index in 0..ncpu {
            let cpu = GuestCpuId::new(index as u32);
            if !allowed(cpu) {
                continue;
            }
            let load = placement.load_of(cpu);
            let wins = match best {
                None => true,
                Some((best_cpu, best_load)) => match load.placement_order(&best_load) {
                    cmp::Ordering::Less => true,
                    // A tie goes to the task's own last CPU, so equal-capacity
                    // CPUs still keep a repeatedly-woken task warm instead of
                    // ping-ponging it to the lowest index.
                    cmp::Ordering::Equal => {
                        placement.last_cpu == Some(cpu) && placement.last_cpu != Some(best_cpu)
                    }
                    cmp::Ordering::Greater => false,
                },
            };
            if wins {
                best = Some((cpu, load));
            }
        }
        match best {
            Some((cpu, _)) => cpu,
            // No allowed CPU in range: the mechanism re-validates and falls
            // back, so any in-range answer is safe here.
            None => placement.last_cpu.unwrap_or(GuestCpuId::new(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bound` executors on a CPU, `idle` of them parked, `queued` rows behind.
    fn load(queued: usize, idle: usize, bound: usize) -> CpuLoad {
        CpuLoad {
            queued,
            idle,
            bound,
        }
    }

    fn place<'a>(
        last: Option<u32>,
        cpus: &'a [CpuLoad],
        affinity: CpuAffinity,
    ) -> TaskPlacement<'a> {
        TaskPlacement {
            task: TaskKey::new(7),
            last_cpu: last.map(GuestCpuId::new),
            affinity,
            cpus,
        }
    }

    #[test]
    fn affinity_round_trips_single_and_all() {
        let all = CpuAffinity::all(4);
        assert_eq!(all.count_allowed(), 4);
        assert!(all.is_allowed(GuestCpuId::new(3)));
        assert!(!all.is_allowed(GuestCpuId::new(4)));

        let one = CpuAffinity::single(GuestCpuId::new(2));
        assert_eq!(one.count_allowed(), 1);
        assert!(one.is_allowed(GuestCpuId::new(2)));
        assert_eq!(one.first_allowed(4), Some(GuestCpuId::new(2)));
        assert_eq!(all.intersect(&one), one);
    }

    #[test]
    fn last_cpu_wins_while_an_executor_there_is_free() {
        let policy = GuestCpuPolicy::new(4);
        // CPU 0 is running one task and has a second executor parked.
        let cpus = [load(0, 1, 2), load(0, 1, 1), load(0, 1, 1), load(0, 1, 1)];
        assert_eq!(
            policy.select_cpu(&place(Some(0), &cpus, CpuAffinity::all(4))),
            GuestCpuId::new(0)
        );
    }

    /// The round-1 defect, stated as a test: CPU 0 has three executors and all
    /// three are running, so its EMPTY queue said "idle" and every wake stuck
    /// there. Availability says CPU 2, which has a parked executor.
    #[test]
    fn a_last_cpu_whose_executors_all_run_yields_even_with_an_empty_queue() {
        let policy = GuestCpuPolicy::new(4);
        let cpus = [load(0, 0, 3), load(0, 0, 3), load(0, 2, 2), load(0, 0, 2)];
        assert_eq!(
            policy.select_cpu(&place(Some(0), &cpus, CpuAffinity::all(4))),
            GuestCpuId::new(2)
        );
    }

    #[test]
    fn a_loaded_last_cpu_yields_to_the_least_loaded_allowed_cpu() {
        let policy = GuestCpuPolicy::new(4);
        let cpus = [load(5, 0, 1), load(4, 0, 1), load(1, 0, 1), load(3, 0, 1)];
        assert_eq!(
            policy.select_cpu(&place(Some(0), &cpus, CpuAffinity::all(4))),
            GuestCpuId::new(2)
        );
    }

    /// Raw counts would call CPU 1 (two runnable) worse than CPU 0 (two
    /// runnable) a tie and take the lower index; per-executor pressure sees
    /// that CPU 1 carries three `M`s and has room.
    #[test]
    fn load_is_measured_per_bound_executor_not_in_raw_rows() {
        let policy = GuestCpuPolicy::new(2);
        let cpus = [load(1, 0, 1), load(1, 0, 3)];
        assert_eq!(
            policy.select_cpu(&place(None, &cpus, CpuAffinity::all(2))),
            GuestCpuId::new(1)
        );
    }

    #[test]
    fn an_offline_cpu_is_never_preferred_to_a_busy_online_one() {
        let policy = GuestCpuPolicy::new(2);
        // CPU 0 has no executor at all; CPU 1 is deeply backed up.
        let cpus = [load(0, 0, 0), load(9, 0, 1)];
        assert_eq!(
            policy.select_cpu(&place(None, &cpus, CpuAffinity::all(2))),
            GuestCpuId::new(1)
        );
    }

    #[test]
    fn a_sticky_wake_needs_a_free_executor_not_just_a_short_queue() {
        let policy = GuestCpuPolicy::new(2);
        // Round 1 took CPU 0 here because its queue was within `sticky_depth`.
        let cpus = [load(1, 0, 1), load(0, 1, 1)];
        assert_eq!(
            policy.select_cpu(&place(Some(0), &cpus, CpuAffinity::all(2))),
            GuestCpuId::new(1)
        );
    }

    #[test]
    fn a_raised_sticky_depth_tolerates_backlog_but_still_needs_an_executor() {
        let policy = GuestCpuPolicy::new(2).with_sticky_depth(1);
        let cpus = [load(1, 1, 2), load(0, 1, 1)];
        assert_eq!(
            policy.select_cpu(&place(Some(0), &cpus, CpuAffinity::all(2))),
            GuestCpuId::new(0)
        );
        // Two rows already queued exceeds the tolerance.
        let cpus = [load(2, 1, 3), load(0, 1, 1)];
        assert_eq!(
            policy.select_cpu(&place(Some(0), &cpus, CpuAffinity::all(2))),
            GuestCpuId::new(1)
        );
    }

    #[test]
    fn equal_capacity_cpus_keep_a_woken_task_on_its_last_cpu() {
        let policy = GuestCpuPolicy::new(4);
        let cpus = [load(0, 0, 1), load(0, 0, 1), load(0, 0, 1), load(0, 0, 1)];
        assert_eq!(
            policy.select_cpu(&place(Some(3), &cpus, CpuAffinity::all(4))),
            GuestCpuId::new(3)
        );
    }

    #[test]
    fn an_affinity_mask_of_one_cpu_pins_placement() {
        let policy = GuestCpuPolicy::new(4);
        let cpus = [load(0, 1, 1), load(0, 1, 1), load(9, 0, 1), load(0, 1, 1)];
        assert_eq!(
            policy.select_cpu(&place(
                Some(0),
                &cpus,
                CpuAffinity::single(GuestCpuId::new(2))
            )),
            GuestCpuId::new(2)
        );
    }
}
