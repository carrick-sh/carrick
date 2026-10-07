//! Wait selection and consuming reap transactions over the authoritative
//! registry. Consumers supply resource access, never a population selector.
use super::registry::{ProcessRegistry, RegistryFailure};
use super::{
    ChildExitSignal, ProcessGroupId, TaskId, TaskKey, TaskRusage, WaitChildClass, WaitTarget,
    Zombie,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitIdentity {
    pub key: TaskKey,
    pub parent: Option<TaskKey>,
    pub tracer: Option<TaskKey>,
    pub group: ProcessGroupId,
    pub exit_signal: ChildExitSignal,
}

pub trait WaitIdentitySource {
    fn wait_identity(&self) -> WaitIdentity;
}

/// Primitive accesses to a live payload. The registry controls which payload
/// is accessed and when event consumption and child charging are permitted.
pub trait WaitLive: WaitIdentitySource {
    type Event;
    type Revision;
    type Error;
    fn wait_children(&self) -> Vec<TaskKey>;
    fn wait_tracees(&self) -> Vec<TaskKey>;
    fn wait_wake_generation(&self) -> TaskWakeGeneration;
    fn wait_event(&self, flags: WaitJobControl, consume: bool) -> Option<Self::Event>;
    fn prepare_reap(&self) -> Result<Self::Revision, Self::Error>;
    /// Infallible publication after revision admission, under registry write.
    fn commit_reap(&mut self, child: TaskKey, charge: TaskRusage, revision: Self::Revision);
}

pub trait WaitZombie<C, U> {
    fn wait_zombie(&self) -> &Zombie<C, U>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitJobControl {
    pub stopped: bool,
    pub continued: bool,
}
impl WaitJobControl {
    pub const NONE: Self = Self {
        stopped: false,
        continued: false,
    };
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitQuery {
    pub target: WaitTarget,
    pub class: WaitChildClass,
    pub job_control: WaitJobControl,
}

/// Created only by the registry scan that found no event. The consumer must
/// retain this value through enrollment, rather than sample the task later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitPrecheck(TaskWakeGeneration);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskWakeGeneration(u64);
impl TaskWakeGeneration {
    pub const fn from_task_counter(value: u64) -> Self {
        Self(value)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}
impl WaitPrecheck {
    pub const fn wake_generation(self) -> TaskWakeGeneration {
        self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitSelection<Z, E> {
    Exited(Z),
    Event(E),
    StillRunning(WaitPrecheck),
    NoChild,
}
/// Read-lock decision for a consuming wait, without cloning an exit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitReadiness {
    Ready,
    StillRunning(WaitPrecheck),
    NoChild,
}

#[derive(Debug)]
pub struct ConsumedWait<Z, E> {
    pub selection: WaitSelection<Z, E>,
    /// Exact parent to which the consumer delivers the post-reap effects.
    pub reaped_parent: Option<TaskKey>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitError<E> {
    UnknownTask(TaskId),
    Busy(TaskId),
    Revision(E),
}

pub type ObservedWait<C, U, L> =
    Result<WaitSelection<Zombie<C, U>, <L as WaitLive>::Event>, WaitError<<L as WaitLive>::Error>>;
pub type ConsumingWait<C, U, L> =
    Result<ConsumedWait<Zombie<C, U>, <L as WaitLive>::Event>, WaitError<<L as WaitLive>::Error>>;

impl<
    C: Copy + Ord,
    L: WaitLive,
    Z,
    R: WaitIdentitySource,
    Reservation,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    pub fn admit_wait(&self, parent: TaskId) -> Result<(), WaitError<L::Error>> {
        if self.reservations.contains_key(&parent) {
            return Err(WaitError::Busy(parent));
        }
        Ok(())
    }

    /// Observe without consuming any event or CPU charge. A consuming caller
    /// may use this as its read-lock fast path, but must rescan under write if
    /// it finds an event; this result does not authorize subsequent removal.
    pub fn scan_wait<U: Clone>(&self, parent: TaskId, query: WaitQuery) -> ObservedWait<C, U, L>
    where
        Z: WaitZombie<C, U>,
    {
        let selected = self.select_wait(parent, query, false)?;
        self.wait_receipt(selected)
    }

    pub fn precheck_wait<U>(
        &self,
        parent: TaskId,
        query: WaitQuery,
    ) -> Result<WaitReadiness, WaitError<L::Error>>
    where
        Z: WaitZombie<C, U>,
    {
        Ok(match self.select_wait::<U>(parent, query, false)? {
            WaitSelection::Exited(_) | WaitSelection::Event(_) => WaitReadiness::Ready,
            WaitSelection::StillRunning(token) => WaitReadiness::StillRunning(token),
            WaitSelection::NoChild => WaitReadiness::NoChild,
        })
    }

    fn wait_receipt<U: Clone>(
        &self,
        selected: WaitSelection<TaskKey, L::Event>,
    ) -> ObservedWait<C, U, L>
    where
        Z: WaitZombie<C, U>,
    {
        Ok(match selected {
            WaitSelection::Exited(key) => {
                let record = self
                    .zombies
                    .get(&key.id)
                    .ok_or(WaitError::UnknownTask(key.id))?;
                WaitSelection::Exited(record.wait_zombie().clone())
            }
            WaitSelection::Event(event) => WaitSelection::Event(event),
            WaitSelection::StillRunning(token) => WaitSelection::StillRunning(token),
            WaitSelection::NoChild => WaitSelection::NoChild,
        })
    }

    /// Select and consume within one write admission. Revision capacity and
    /// both topology reservations are checked before publishing any reap.
    pub fn consume_wait<U: Clone>(
        &mut self,
        parent_id: TaskId,
        query: WaitQuery,
    ) -> ConsumingWait<C, U, L>
    where
        Z: WaitZombie<C, U>,
    {
        self.admit_wait(parent_id)?;
        let selected = self.select_wait(parent_id, query, true)?;
        let selection = self.wait_receipt(selected)?;
        let mut reaped_parent = None;
        if let WaitSelection::Exited(zombie) = &selection {
            self.admit_wait(zombie.key.id)?;
            let parent = self
                .tasks
                .get(&parent_id)
                .ok_or(WaitError::UnknownTask(parent_id))?;
            let revision = parent.prepare_reap().map_err(WaitError::Revision)?;
            reaped_parent = Some(parent.wait_identity().key);
            self.zombies.remove(&zombie.key.id);
            self.remove_group_member(zombie.process_group, zombie.session, zombie.key);
            // No fallible operation follows removal. The same write guard
            // owns the parent entry that was admitted above.
            if let Some(parent) = self.tasks.get_mut(&parent_id) {
                parent.commit_reap(zombie.key, zombie.total_charge_to_reaper(), revision);
            }
        }
        Ok(ConsumedWait {
            selection,
            reaped_parent,
        })
    }

    fn select_wait<U>(
        &self,
        parent_id: TaskId,
        query: WaitQuery,
        consume: bool,
    ) -> Result<WaitSelection<TaskKey, L::Event>, WaitError<L::Error>>
    where
        Z: WaitZombie<C, U>,
    {
        let parent_record = self
            .tasks
            .get(&parent_id)
            .ok_or(WaitError::UnknownTask(parent_id))?;
        let parent = parent_record.wait_identity().key;
        let children = parent_record.wait_children();
        let tracees = parent_record.wait_tracees();
        let traced_non_children: Vec<_> = tracees
            .into_iter()
            .filter(|key| !children.contains(key))
            .collect();
        for child in &children {
            if let Some(record) = self.zombies.get(&child.id) {
                let zombie = record.wait_zombie();
                if zombie.key == *child
                    && zombie.parent == Some(parent)
                    && query.class.admits(zombie.exit_signal)
                    && query.target.admits(*child, zombie.process_group)
                {
                    return Ok(WaitSelection::Exited(*child));
                }
            }
        }
        for child in &children {
            if let Some(record) = self.tasks.get(&child.id)
                && query.admits_child(*child, parent, record.wait_identity())
                && let Some(event) = record.wait_event(query.job_control, consume)
            {
                return Ok(WaitSelection::Event(event));
            }
        }
        // Existing host semantics: non-child tracees report stop/continue,
        // regardless of clone class. Their exit remains with the real parent.
        let trace_flags = WaitJobControl {
            stopped: true,
            continued: query.job_control.continued,
        };
        for tracee in &traced_non_children {
            if let Some(record) = self.tasks.get(&tracee.id)
                && query.admits_tracee(*tracee, parent, record.wait_identity())
                && let Some(event) = record.wait_event(trace_flags, consume)
            {
                return Ok(WaitSelection::Event(event));
            }
        }
        let live_tracee = traced_non_children.iter().any(|key| {
            self.tasks
                .get(&key.id)
                .is_some_and(|record| query.admits_tracee(*key, parent, record.wait_identity()))
        });
        let live_child = live_tracee
            || children.iter().any(|key| {
                self.tasks
                    .get(&key.id)
                    .map(|record| record.wait_identity())
                    .or_else(|| {
                        self.retiring_tasks
                            .get(&key.id)
                            .map(|record| record.wait_identity())
                    })
                    .is_some_and(|identity| query.admits_child(*key, parent, identity))
            });
        Ok(if live_child {
            WaitSelection::StillRunning(WaitPrecheck(parent_record.wait_wake_generation()))
        } else {
            WaitSelection::NoChild
        })
    }
}
impl WaitQuery {
    fn admits_child(self, key: TaskKey, parent: TaskKey, identity: WaitIdentity) -> bool {
        identity.key == key
            && identity.parent == Some(parent)
            && self.class.admits(identity.exit_signal)
            && self.target.admits(key, identity.group)
    }
    fn admits_tracee(self, key: TaskKey, parent: TaskKey, identity: WaitIdentity) -> bool {
        identity.key == key
            && identity.tracer == Some(parent)
            && self.target.admits(key, identity.group)
    }
}
