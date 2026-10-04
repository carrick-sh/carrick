//! Graph-local deterministic scheduling for opted-in VM-free scenarios.
//! The hooks are absent from release builds of the example backend, and this
//! crate is absent from Carrick's product dependency closure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use carrick_kernel::kernel::objects::ExecutionGeneration;
use carrick_kernel::kernel::{TaskKey, objects::thread::ThreadKey};
use carrick_observability::work_meter::WorkSnapshot;
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::operand::Step;

const SCHEMA_VERSION: u32 = 1;
const GENERATOR_VERSION: u32 = 3;
const WATCHDOG: Duration = Duration::from_secs(5);

/// A source boundary at which an actor may relinquish its test permit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Point {
    Step,
    DispatchUnlocked,
    ContinuationBuild,
    AwaitParked,
    WaitEnrolled,
    FutexWakePublished,
    WaitResumed,
    FdDrained,
    TerminalUnlocked,
    TerminalPublished,
    Finish,
    Kernel(carrick_kernel::kernel::schedule::Point),
    AwaitEvent,
}

/// Exact kernel identity, including both incarnation serials and CPU generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Actor {
    pub task_id: i32,
    pub task_serial: u64,
    pub thread_id: i32,
    pub thread_serial: u64,
    pub execution_generation: u64,
}

impl Actor {
    pub fn from_kernel(task: TaskKey, thread: ThreadKey, generation: ExecutionGeneration) -> Self {
        Self {
            task_id: task.id.raw(),
            task_serial: task.serial.raw(),
            thread_id: thread.tid.raw(),
            thread_serial: thread.serial.raw(),
            execution_generation: generation.raw(),
        }
    }
}

/// One selected transition. The full eligible set makes replay reject drift.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub actor: Actor,
    pub point: Point,
    pub visit: usize,
    pub runnable: Vec<Actor>,
    pub next: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<carrick_kernel::kernel::schedule::AuthorityStamp>,
}

/// Portable receipt for strict replay and retained regression fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScheduleReceipt {
    pub schema_version: u32,
    pub generator_version: u32,
    pub seed: u64,
    pub source_hash: String,
    pub fixture_hash: String,
    pub backend: String,
    pub scale: usize,
    pub decisions: Vec<Decision>,
    pub result: String,
    pub work_snapshot: Option<WorkSnapshot>,
}

#[derive(Clone)]
pub struct Schedule(Arc<(Mutex<State>, Condvar)>);

struct State {
    seed: u64,
    random: u64,
    max_transitions: usize,
    actors: BTreeSet<Actor>,
    parked: BTreeMap<Actor, u64>,
    admission_waiters: BTreeSet<Actor>,
    observed: BTreeSet<(Actor, Point)>,
    dependencies: BTreeMap<Actor, (Actor, Point)>,
    current: Option<Actor>,
    decisions: Vec<Decision>,
    visits: BTreeMap<(Actor, Point), usize>,
    replay: Option<ScheduleReceipt>,
    source_hash: String,
    fixture_hash: String,
    scale: usize,
    started: bool,
    failure: Option<String>,
    allowed_source_pair: Option<(String, String)>,
}

impl Schedule {
    pub fn explore(seed: u64) -> Self {
        Self(Arc::new((
            Mutex::new(State {
                seed,
                random: seed,
                max_transitions: 10_000,
                actors: BTreeSet::new(),
                parked: BTreeMap::new(),
                admission_waiters: BTreeSet::new(),
                observed: BTreeSet::new(),
                dependencies: BTreeMap::new(),
                current: None,
                decisions: Vec::new(),
                visits: BTreeMap::new(),
                replay: None,
                source_hash: String::new(),
                fixture_hash: String::new(),
                scale: 1,
                started: false,
                failure: None,
                allowed_source_pair: None,
            }),
            Condvar::new(),
        )))
    }

    pub fn replay(receipt: ScheduleReceipt) -> Self {
        let schedule = Self::explore(receipt.seed);
        schedule.0.0.lock().replay = Some(receipt);
        schedule
    }

    pub fn max_transitions(self, max: usize) -> Self {
        self.0.0.lock().max_transitions = max;
        self
    }

    /// Drive public kernel operations on pre-registered, exact actors. No
    /// dispatcher mutex hides admission races, and no transaction is copied.
    #[cfg(debug_assertions)]
    pub fn run_operations(
        &self,
        kernel: &Arc<carrick_kernel::kernel::Kernel>,
        fixture: &str,
        scale: usize,
        contexts: &[carrick_kernel::kernel::KernelContext],
        operation: impl Fn(usize, &OperationActor<'_>) + Sync,
    ) -> Result<ScheduleReceipt, String> {
        use carrick_kernel::kernel::schedule::{Authority, Point as KPoint};
        let actors: Vec<_> = contexts
            .iter()
            .map(|context| Actor {
                task_id: context.task().key().id.raw(),
                task_serial: context.task().key().serial.raw(),
                thread_id: context.thread().key().tid.raw(),
                thread_serial: context.thread().key().serial.raw(),
                // Zero records the absence of an execution binding; it never
                // fabricates an initial or successor execution generation.
                execution_generation: context
                    .thread()
                    .execution_state()
                    .generation()
                    .map_or(0, |g| g.raw()),
            })
            .collect();
        let root = *actors.first().ok_or("operation fixture has no actors")?;
        if scale == 0 {
            return Err("operation fixture has zero scale".into());
        }
        self.start_hash(hex_digest(fixture.as_bytes()), root, scale)?;
        for actor in &actors[1..] {
            self.register(*actor)?;
        }
        let schedule = self.clone();
        let identities = actors.clone();
        kernel.schedule_hooks().set(Some(Arc::new(move |event| {
            let subject = event.actor.or(match event.authority {
                Authority::Thread(subject) => Some(subject),
                _ => None,
            });
            let Some(actor) = subject
                .and_then(|subject| {
                    identities.iter().find(|actor| {
                        actor.task_id == subject.task.id.raw()
                            && actor.task_serial == subject.task.serial.raw()
                            && actor.thread_id == subject.thread.tid.raw()
                            && actor.thread_serial == subject.thread.serial.raw()
                            && subject.generation.map_or(0, |generation| generation.raw())
                                == actor.execution_generation
                    })
                })
                .copied()
            else {
                return;
            };
            let outcome = match event.point {
                KPoint::CredentialWaiting => schedule.park_admission(actor),
                KPoint::CredentialResumed => schedule
                    .enter(actor)
                    .and_then(|()| schedule.point(actor, Point::WaitResumed)),
                KPoint::AdmissionReleased
                    if matches!(event.authority, Authority::Thread(target) if Some(target) != event.actor) =>
                {
                    let Authority::Thread(target) = event.authority else { unreachable!() };
                    let waiter = identities.iter().find(|candidate| {
                        candidate.task_id == target.task.id.raw()
                            && candidate.task_serial == target.task.serial.raw()
                            && candidate.thread_id == target.thread.tid.raw()
                            && candidate.thread_serial == target.thread.serial.raw()
                            && candidate.execution_generation == target.generation.map_or(0, |g| g.raw())
                    });
                    match waiter {
                        Some(waiter) => schedule.publish_admission_wake(actor, *waiter, event.authority.stamp()),
                        None => Err("admission release names an unregistered waiter".into()),
                    }
                },
                point => schedule.point_with_authority(
                    actor,
                    Point::Kernel(point),
                    Some(event.authority.stamp()),
                ),
            };
            if let Err(error) = outcome {
                schedule.abort(error);
            }
        })));
        std::thread::scope(|scope| {
            for (index, context) in contexts.iter().enumerate() {
                let operation = &operation;
                let actors = &actors;
                scope.spawn(move || {
                    let actor = actors[index];
                    if let Err(error) = self.enter(actor) {
                        self.abort(error);
                        return;
                    }
                    let handle = OperationActor {
                        schedule: self,
                        kernel,
                        subject: carrick_kernel::kernel::schedule::Subject::from_context(context),
                        actor,
                    };
                    operation(index, &handle);
                    if let Err(error) = self.finish(actor) {
                        self.abort(error);
                    }
                });
            }
        });
        kernel.schedule_hooks().set(None);
        self.receipt("operations drained", None)
    }

    #[cfg(debug_assertions)]
    fn await_point(&self, actor: Actor, dependency: (Actor, Point)) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.observed.contains(&dependency) {
            return Ok(());
        }
        if state.current != Some(actor) || !state.actors.remove(&actor) {
            return Err("dependency waiter lacks permit".into());
        }
        state.dependencies.insert(actor, dependency);
        if let Err(error) = Self::choose(&mut state, actor, Point::AwaitEvent) {
            state.failure = Some(error);
        }
        wake.notify_all();
        while !state.actors.contains(&actor) && state.failure.is_none() {
            if wake.wait_for(&mut state, WATCHDOG).timed_out() {
                state.failure = Some(format!(
                    "stranded schedule dependencies: {:?}",
                    state.dependencies
                ));
                wake.notify_all();
            }
        }
        if let Some(error) = state.failure.clone() {
            return Err(error);
        }
        drop(state);
        self.enter(actor)
    }

    /// Explicitly allow exactly one known-bad -> fixed source comparison.
    pub fn allow_source_pair(self, bad: &str, fixed: &str) -> Self {
        self.0.0.lock().allowed_source_pair = Some((bad.into(), fixed.into()));
        self
    }

    pub(crate) fn start(&self, script: &[Step], root: Actor) -> Result<(), String> {
        if script.iter().any(has_uncontrolled_step) {
            return Err(
                "scheduled scenario contains an uncontrolled host checkpoint or wait".into(),
            );
        }
        self.start_hash(hex_digest(format!("{script:?}").as_bytes()), root, 1)
    }

    fn start_hash(&self, fixture_hash: String, root: Actor, scale: usize) -> Result<(), String> {
        let (lock, _) = &*self.0;
        let mut state = lock.lock();
        if state.started {
            return Err("schedule already started".into());
        }
        state.source_hash = source_hash()?;
        state.fixture_hash = fixture_hash;
        state.scale = scale;
        if let Some(replay) = &state.replay {
            if replay.schema_version != SCHEMA_VERSION
                || replay.generator_version != GENERATOR_VERSION
                || replay.backend != backend_id()
                || replay.scale != state.scale
                || replay.fixture_hash != state.fixture_hash
            {
                return Err("replay schema, backend, scale or fixture mismatch".into());
            }
            if replay.source_hash != state.source_hash
                && state.allowed_source_pair.as_ref()
                    != Some(&(replay.source_hash.clone(), state.source_hash.clone()))
            {
                return Err("replay source hash mismatch".into());
            }
        }
        state.actors.insert(root);
        state.current = Some(root);
        state.started = true;
        Ok(())
    }

    pub(crate) fn register(&self, actor: Actor) -> Result<(), String> {
        let mut state = self.0.0.lock();
        if !state.started
            || state.parked.contains_key(&actor)
            || state.admission_waiters.contains(&actor)
            || state.dependencies.contains_key(&actor)
            || !state.actors.insert(actor)
        {
            return Err("duplicate or premature schedule actor".into());
        }
        Ok(())
    }

    pub(crate) fn enter(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if !state.actors.contains(&actor)
            && !state.parked.contains_key(&actor)
            && !state.admission_waiters.contains(&actor)
            && !state.dependencies.contains_key(&actor)
        {
            return Err("unregistered schedule actor".into());
        }
        while state.current != Some(actor) && state.failure.is_none() {
            if wake.wait_for(&mut state, WATCHDOG).timed_out() {
                state.failure = Some(format!("schedule stranded actor {actor:?}"));
                wake.notify_all();
            }
        }
        state.failure.clone().map_or(Ok(()), Err)
    }

    fn choose(state: &mut State, actor: Actor, point: Point) -> Result<(), String> {
        Self::choose_with_authority(state, actor, point, None)
    }

    fn choose_with_authority(
        state: &mut State,
        actor: Actor,
        point: Point,
        authority: Option<carrick_kernel::kernel::schedule::AuthorityStamp>,
    ) -> Result<(), String> {
        if state.decisions.len() >= state.max_transitions {
            return Err("schedule transition budget exceeded".into());
        }
        state.observed.insert((actor, point));
        let ready: Vec<_> = state
            .dependencies
            .iter()
            .filter(|(_, dependency)| **dependency == (actor, point))
            .map(|(waiting, _)| *waiting)
            .collect();
        for waiting in ready {
            state.dependencies.remove(&waiting);
            state.actors.insert(waiting);
        }
        let runnable: Vec<_> = state.actors.iter().copied().collect();
        // Markers within the terminal sequence only observe. In particular,
        // FdDrained runs under the dispatcher mutex and must never park there.
        let observation = matches!(point, Point::FdDrained | Point::TerminalPublished)
            || matches!(point, Point::Kernel(p) if p.observation_only());
        let generated = if observation {
            Some(actor)
        } else {
            state.random = state
                .random
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1);
            if runnable.is_empty() {
                None
            } else {
                Some(runnable[(state.random >> 14) as usize % runnable.len()])
            }
        };
        let visits = state.visits.entry((actor, point)).or_default();
        let visit = *visits;
        *visits += 1;
        let next = if let Some(replay) = &state.replay {
            let expected = replay
                .decisions
                .get(state.decisions.len())
                .ok_or("replay exhausted before execution ended")?;
            if expected.actor != actor
                || expected.point != point
                || expected.visit != visit
                || expected.authority != authority
            {
                return Err(format!(
                    "replay point, actor, visit or authority drift at {}",
                    state.decisions.len()
                ));
            }
            if expected.runnable != runnable {
                return Err(format!(
                    "replay runnable-set drift at {}",
                    state.decisions.len()
                ));
            }
            if expected.next.is_none() != runnable.is_empty()
                || expected
                    .next
                    .is_some_and(|selected| !runnable.contains(&selected))
            {
                return Err("replay selected an ineligible actor".into());
            }
            if observation && expected.next != Some(actor) {
                return Err("replay moved an actor at an observation-only point".into());
            }
            expected.next
        } else {
            generated
        };
        state.decisions.push(Decision {
            actor,
            point,
            visit,
            runnable,
            next,
            authority,
        });
        state.current = next;
        Ok(())
    }

    pub(crate) fn point(&self, actor: Actor, point: Point) -> Result<(), String> {
        self.point_with_authority(actor, point, None)
    }

    fn point_with_authority(
        &self,
        actor: Actor,
        point: Point,
        authority: Option<carrick_kernel::kernel::schedule::AuthorityStamp>,
    ) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        {
            let mut state = lock.lock();
            if state.current != Some(actor) {
                return Err("schedule actor lacks permit".into());
            }
            if let Err(error) = Self::choose_with_authority(&mut state, actor, point, authority) {
                state.failure = Some(error.clone());
                wake.notify_all();
                return Err(error);
            }
            wake.notify_all();
        }
        self.enter(actor)
    }

    /// Admission waiting releases the permit but host condvar delivery cannot
    /// restore eligibility. Only the reservation owner's release event can.
    #[cfg(debug_assertions)]
    fn park_admission(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.current != Some(actor) || !state.actors.remove(&actor) {
            return Err("admission waiter lacks permit".into());
        }
        state.admission_waiters.insert(actor);
        if let Err(error) = Self::choose(&mut state, actor, Point::WaitEnrolled) {
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        wake.notify_all();
        Ok(())
    }

    #[cfg(debug_assertions)]
    fn publish_admission_wake(
        &self,
        actor: Actor,
        waiter: Actor,
        authority: carrick_kernel::kernel::schedule::AuthorityStamp,
    ) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.current != Some(actor) || !state.admission_waiters.remove(&waiter) {
            let error = "admission release lacks a permit or matching waiter".to_string();
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        state.actors.insert(waiter);
        if let Err(error) = Self::choose_with_authority(
            &mut state,
            actor,
            Point::Kernel(carrick_kernel::kernel::schedule::Point::AdmissionReleased),
            Some(authority),
        ) {
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        wake.notify_all();
        drop(state);
        self.enter(actor)
    }

    /// A guest futex continuation releases its permit after enrollment. The
    /// host thread waits for the scheduler, never for host event timing.
    pub(crate) fn park(&self, actor: Actor, futex_addr: u64) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.current != Some(actor) || !state.actors.remove(&actor) {
            return Err("parking actor lacks permit".into());
        }
        state.parked.insert(actor, futex_addr);
        if let Err(error) = Self::choose(&mut state, actor, Point::WaitEnrolled) {
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        wake.notify_all();
        Ok(())
    }

    /// A successful in-zone futex wake has already published the wait-service
    /// event synchronously. Admit its sole matching waiter as a recorded
    /// scheduler decision, before the waker can relinquish its permit.
    pub(crate) fn publish_futex_wake(
        &self,
        actor: Actor,
        futex_addr: u64,
        count: u64,
    ) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.current != Some(actor) {
            return Err("futex wake publisher lacks permit".into());
        }
        let matching: Vec<_> = state
            .parked
            .iter()
            .filter_map(|(waiter, addr)| (*addr == futex_addr).then_some(*waiter))
            .collect();
        if count != 1 || matching.len() != 1 {
            let error = format!(
                "external readiness: scheduled futex wake cannot identify one waiter (count={count}, matching={})",
                matching.len()
            );
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        let waiter = matching[0];
        state.parked.remove(&waiter);
        state.actors.insert(waiter);
        if let Err(error) = Self::choose(&mut state, actor, Point::FutexWakePublished) {
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        wake.notify_all();
        drop(state);
        self.enter(actor)
    }

    pub(crate) fn finish(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.failure.is_some() {
            state.actors.remove(&actor);
            state.parked.remove(&actor);
            state.admission_waiters.remove(&actor);
            state.dependencies.remove(&actor);
            wake.notify_all();
            return Ok(());
        }
        if state.current != Some(actor) || !state.actors.remove(&actor) {
            return Err("retiring actor lacks permit".into());
        }
        let outcome = Self::choose(&mut state, actor, Point::Finish);
        if let Err(error) = &outcome {
            state.failure = Some(error.clone());
        }
        wake.notify_all();
        outcome
    }

    pub(crate) fn abort(&self, reason: String) {
        let (lock, wake) = &*self.0;
        lock.lock().failure = Some(reason);
        wake.notify_all();
    }

    pub fn receipt(
        &self,
        result: impl Into<String>,
        work_snapshot: Option<WorkSnapshot>,
    ) -> Result<ScheduleReceipt, String> {
        let state = self.0.0.lock();
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        if !state.started
            || !state.actors.is_empty()
            || !state.parked.is_empty()
            || !state.admission_waiters.is_empty()
            || !state.dependencies.is_empty()
        {
            return Err("schedule actors did not drain".into());
        }
        if let Some(replay) = &state.replay
            && replay.decisions.len() != state.decisions.len()
        {
            return Err("unconsumed replay suffix".into());
        }
        let result = result.into();
        if let Some(replay) = &state.replay
            && replay.source_hash == state.source_hash
            && (replay.result != result || replay.work_snapshot != work_snapshot)
        {
            return Err(format!(
                "replay result or work snapshot drift: expected result {:?}, observed {:?}; expected work {:?}, observed work {:?}",
                replay.result, result, replay.work_snapshot, work_snapshot
            ));
        }
        Ok(ScheduleReceipt {
            schema_version: SCHEMA_VERSION,
            generator_version: GENERATOR_VERSION,
            seed: state.seed,
            source_hash: state.source_hash.clone(),
            fixture_hash: state.fixture_hash.clone(),
            backend: backend_id(),
            scale: state.scale,
            decisions: state.decisions.clone(),
            result,
            work_snapshot,
        })
    }
}

/// A public-operation actor can await an admitted event without polling or
/// holding an OS lock. Points use the same graph hook as product operations.
#[cfg(debug_assertions)]
pub struct OperationActor<'a> {
    schedule: &'a Schedule,
    kernel: &'a Arc<carrick_kernel::kernel::Kernel>,
    subject: carrick_kernel::kernel::schedule::Subject,
    actor: Actor,
}
#[cfg(debug_assertions)]
impl OperationActor<'_> {
    pub fn identity(&self) -> Actor {
        self.actor
    }
    pub fn point(&self, point: carrick_kernel::kernel::schedule::Point) {
        carrick_kernel::schedule_point!(
            self.kernel.schedule_hooks(),
            carrick_kernel::kernel::schedule::Event {
                point,
                actor: Some(self.subject),
                authority: carrick_kernel::kernel::schedule::Authority::Thread(self.subject),
            }
        );
    }
    pub fn authority_point(
        &self,
        point: carrick_kernel::kernel::schedule::Point,
        authority: carrick_kernel::kernel::schedule::Authority,
    ) {
        carrick_kernel::schedule_point!(
            self.kernel.schedule_hooks(),
            carrick_kernel::kernel::schedule::Event {
                point,
                authority,
                actor: Some(self.subject),
            }
        );
    }
    pub fn after(&self, actor: Actor, point: Point) -> Result<(), String> {
        self.schedule.await_point(self.actor, (actor, point))
    }
    /// Publish a released reservation as a scheduling decision, naming the
    /// exact admitted waiter. Call only after releasing the real reservation.
    pub fn release_admission(&self, waiter: &carrick_kernel::kernel::KernelContext) {
        self.authority_point(
            carrick_kernel::kernel::schedule::Point::AdmissionReleased,
            carrick_kernel::kernel::schedule::Authority::Thread(
                carrick_kernel::kernel::schedule::Subject::from_context(waiter),
            ),
        );
    }
}

fn has_uncontrolled_step(step: &Step) -> bool {
    match step {
        Step::AwaitCheckpoint(_) | Step::SignalCheckpoint(_) => true,
        Step::ChildMarker(children) => children.iter().any(has_uncontrolled_step),
        _ => false,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn backend_id() -> String {
    "kernel-example/portable".into()
}

fn source_hash() -> Result<String, String> {
    static SOURCE_HASH: OnceLock<Result<String, String>> = OnceLock::new();
    SOURCE_HASH.get_or_init(compute_source_hash).clone()
}

fn compute_source_hash() -> Result<String, String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    collect_rust_sources(&root.join("crates/carrick-kernel/src"), &mut paths)?;
    collect_rust_sources(&root.join("crates/carrick-kernel-example/src"), &mut paths)?;
    for name in ["carrick-sched-core", "carrick-fd-core", "carrick-pipe-core"] {
        collect_rust_sources(&root.join("crates").join(name).join("src"), &mut paths)?;
    }
    paths.push(root.join("crates/carrick-kernel-example/tests/admission_interleavings.rs"));
    paths.push(root.join("crates/carrick-kernel-example/tests/schedule_replay.rs"));
    paths.sort();
    let mut hash = Sha256::new();
    for path in paths {
        let relative = path.strip_prefix(&root).map_err(|e| e.to_string())?;
        hash.update(relative.to_string_lossy().as_bytes());
        hash.update([0]);
        hash.update(std::fs::read(&path).map_err(|e| format!("hash {}: {e}", relative.display()))?);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn collect_rust_sources(
    dir: &std::path::Path,
    paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("list {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("list {}: {e}", dir.display()))?;
        let kind = entry.file_type().map_err(|e| format!("source type: {e}"))?;
        if kind.is_dir() {
            collect_rust_sources(&entry.path(), paths)?;
        } else if kind.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rs")
        {
            paths.push(entry.path());
        }
    }
    Ok(())
}

pub use carrick_kernel::schedule_point;
