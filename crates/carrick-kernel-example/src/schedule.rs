//! Graph-local deterministic scheduling for opted-in VM-free scenarios.
//! The hooks are absent from release builds of the example backend, and this
//! crate is absent from Carrick's product dependency closure.

use std::collections::BTreeSet;
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
const GENERATOR_VERSION: u32 = 2;
const WATCHDOG: Duration = Duration::from_secs(5);

/// A source boundary at which an actor may relinquish its test permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Point {
    Step,
    DispatchUnlocked,
    ContinuationBuild,
    AwaitParked,
    WaitEnrolled,
    WaitResumed,
    FdDrained,
    TerminalUnlocked,
    TerminalPublished,
    Finish,
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
    parked: BTreeSet<Actor>,
    current: Option<Actor>,
    decisions: Vec<Decision>,
    replay: Option<ScheduleReceipt>,
    source_hash: String,
    fixture_hash: String,
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
                parked: BTreeSet::new(),
                current: None,
                decisions: Vec::new(),
                replay: None,
                source_hash: String::new(),
                fixture_hash: String::new(),
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

    /// Explicitly allow exactly one known-bad -> fixed source comparison.
    pub fn allow_source_pair(self, bad: &str, fixed: &str) -> Self {
        self.0.0.lock().allowed_source_pair = Some((bad.into(), fixed.into()));
        self
    }

    pub(crate) fn start(&self, script: &[Step], root: Actor) -> Result<(), String> {
        let (lock, _) = &*self.0;
        let mut state = lock.lock();
        if state.started {
            return Err("schedule already started".into());
        }
        if script.iter().any(has_uncontrolled_step) {
            return Err(
                "scheduled scenario contains an uncontrolled host checkpoint or wait".into(),
            );
        }
        state.source_hash = source_hash()?;
        state.fixture_hash = hex_digest(format!("{script:?}").as_bytes());
        if let Some(replay) = &state.replay {
            if replay.schema_version != SCHEMA_VERSION
                || replay.generator_version != GENERATOR_VERSION
                || replay.backend != backend_id()
                || replay.scale != 1
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
        if !state.started || state.parked.contains(&actor) || !state.actors.insert(actor) {
            return Err("duplicate or premature schedule actor".into());
        }
        Ok(())
    }

    pub(crate) fn enter(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if !state.actors.contains(&actor) {
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
        if state.decisions.len() >= state.max_transitions {
            return Err("schedule transition budget exceeded".into());
        }
        let runnable: Vec<_> = state.actors.iter().copied().collect();
        // Markers within the terminal sequence only observe. In particular,
        // FdDrained runs under the dispatcher mutex and must never park there.
        let observation = matches!(point, Point::FdDrained | Point::TerminalPublished);
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
        let visit = state
            .decisions
            .iter()
            .filter(|d| d.actor == actor && d.point == point)
            .count();
        let next = if let Some(replay) = &state.replay {
            let expected = replay
                .decisions
                .get(state.decisions.len())
                .ok_or("replay exhausted before execution ended")?;
            if expected.actor != actor || expected.point != point || expected.visit != visit {
                return Err(format!(
                    "replay point, actor or visit drift at {}",
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
        });
        state.current = next;
        Ok(())
    }

    pub(crate) fn point(&self, actor: Actor, point: Point) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        {
            let mut state = lock.lock();
            if state.current != Some(actor) {
                return Err("schedule actor lacks permit".into());
            }
            if let Err(error) = Self::choose(&mut state, actor, point) {
                state.failure = Some(error.clone());
                wake.notify_all();
                return Err(error);
            }
            wake.notify_all();
        }
        self.enter(actor)
    }

    /// A guest continuation releases its permit after enrollment. Its host
    /// thread may wait for the event, but it cannot occupy an execution lane.
    pub(crate) fn park(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.current != Some(actor) || !state.actors.remove(&actor) {
            return Err("parking actor lacks permit".into());
        }
        state.parked.insert(actor);
        if let Err(error) = Self::choose(&mut state, actor, Point::WaitEnrolled) {
            state.failure = Some(error.clone());
            wake.notify_all();
            return Err(error);
        }
        wake.notify_all();
        Ok(())
    }

    /// A published event makes the exact actor eligible again. Re-entry waits
    /// for a permit rather than consuming a host worker's guest capacity.
    pub(crate) fn unpark(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        {
            let mut state = lock.lock();
            if !state.parked.remove(&actor) || !state.actors.insert(actor) {
                return Err("unparking actor was not parked".into());
            }
            if state.current.is_none() {
                state.current = Some(actor);
            }
            wake.notify_all();
        }
        self.enter(actor)?;
        self.point(actor, Point::WaitResumed)
    }

    pub(crate) fn parked_count(&self) -> usize {
        self.0.0.lock().parked.len()
    }

    /// A successful in-zone wake publishes its event before the waker can
    /// select the next actor. This closes the host-thread delivery gap between
    /// the kernel producer and the test scheduler's runnable set.
    pub(crate) fn await_wake_publication(
        &self,
        actor: Actor,
        parked_before_wake: usize,
    ) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        while state.parked.len() >= parked_before_wake && state.failure.is_none() {
            if state.current != Some(actor) {
                return Err("wake publisher lacks permit".into());
            }
            if wake.wait_for(&mut state, WATCHDOG).timed_out() {
                return Err("successful wake did not publish an event".into());
            }
        }
        state.failure.clone().map_or(Ok(()), Err)
    }

    pub(crate) fn finish(&self, actor: Actor) -> Result<(), String> {
        let (lock, wake) = &*self.0;
        let mut state = lock.lock();
        if state.failure.is_some() {
            state.actors.remove(&actor);
            state.parked.remove(&actor);
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
        if !state.started || !state.actors.is_empty() || !state.parked.is_empty() {
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
            scale: 1,
            decisions: state.decisions.clone(),
            result,
            work_snapshot,
        })
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
    format!(
        "kernel-example/{}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
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

/// One source-level hook API. Optimized builds contain no call or point value.
#[macro_export]
macro_rules! schedule_point {
    ($shared:expr, $task:expr, $point:expr) => {
        #[cfg(debug_assertions)]
        if let Some(schedule) = &$shared.schedule {
            schedule
                .point($task.schedule_actor(), $point)
                .map_err($crate::scripted::ExampleError::Schedule)?;
        }
    };
}
