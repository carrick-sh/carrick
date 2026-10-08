//! Native process-resource adapter over the single shared process registry.
//!
//! The enclosing native graph guard supplies exclusive access to this owner.
//! Child admission retains that access through publication; exit custody retains
//! it through shared topology/receipt publication and exact reservation release.
//! Cancellation and signal snapshots occur after the enclosing guard is dropped.
//! This adapter returns custody, never syscall completion or a CPU/MM operation.
extern crate alloc;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use carrick_sched_core::process::birth::{
    AdmittedProcessBirth, BirthAttachment, BirthError, BirthLive, BirthSnapshot,
};
use carrick_sched_core::process::exit::{
    ExitEffectSource, ExitError, ExitLive, ExitLivePublication, ExitMember, ExitNotificationSource,
    ExitParentPermit, ExitParentTarget, ExitRetiring, ExitSignalSource, ExitZombie,
    ExitZombiePublication, PendingExitEffects, PreparedExitParticipant, PreparedExitTopology,
    ReadyExitEffects, ReleasedTaskSet, ReservedTaskSet, TaskGraphReservation, TaskRevision,
    TaskSetError,
};
use carrick_sched_core::process::registry::{
    ProcessGroupRecord, ProcessRegistry, RegistryFailure, RegistryInvariant, SessionRecord,
};
use carrick_sched_core::process::wait::{
    ConsumedWait, TaskWakeGeneration, WaitError, WaitIdentity, WaitIdentitySource, WaitJobControl,
    WaitLive, WaitQuery, WaitReadiness, WaitSelection, WaitZombie,
};
use carrick_sched_core::process::{
    ChildExitSignal, LinuxWaitStatus, ProcessRelations, SessionId, TaskId, TaskIdentity, TaskKey,
    TaskLifecycle, TaskRusage, Zombie,
};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

/// Primitive resource accesses for this row only. These hooks never choose a
/// process identity, adopter, zombie, exit target, mapping or process population.
pub trait NativeProcessCustody {
    type Context: Copy;
    type Claim;
    type Event;
    type Credit;
    type Error;
    type Transaction: Copy + Eq;
    type Member: ExitMember;
    type Resources;
    type SignalTarget: ExitSignalSource;
    fn next_revision(&self, current: TaskRevision) -> Result<TaskRevision, Self::Error>;
    fn reserve_exit_credit(&self, current: TaskRevision) -> Result<Self::Credit, Self::Error>;
    fn consume_exit_credit(&self, credit: &mut Self::Credit, current: TaskRevision)
    -> TaskRevision;
    fn wait_event(&self, flags: WaitJobControl, consume: bool) -> Option<Self::Event>;
    fn wake_generation(&self) -> TaskWakeGeneration;
    fn own_members_and_resources(&self) -> (Vec<Self::Member>, Self::Resources);
    /// Retain a handle only; signal locks are sampled by shared `prepare()`
    /// after cancellation and after the enclosing registry guard is released.
    fn signal_target(&self) -> Self::SignalTarget;
    fn autoreaps_children(&self) -> bool;
    fn own_rusage(&self) -> TaskRusage;
}

/// Immutable task identity and historical receipt metadata. Parent/children are
/// stored only in the shared ProcessRelations belonging to the same live row.
pub struct GuestTaskMetadata<C, U> {
    pub key: TaskKey,
    pub container: C,
    pub namespace_pid: u32,
    pub identity: TaskIdentity,
    pub namespace_process_group: u32,
    pub namespace_session: u32,
    pub ruid: U,
    pub euid: U,
    pub exit_signal: ChildExitSignal,
    pub diagnostic_name: String,
}

pub struct GuestTask<C, U, N: NativeProcessCustody> {
    metadata: GuestTaskMetadata<C, U>,
    relations: ProcessRelations,
    revision: TaskRevision,
    exiting: AtomicBool,
    context: N::Context,
    native: N,
    claim: N::Claim,
    tracer: Option<TaskKey>,
    tracees: BTreeSet<TaskKey>,
    children_rusage: TaskRusage,
}
impl<C, U, N: NativeProcessCustody> GuestTask<C, U, N> {
    pub fn new(
        metadata: GuestTaskMetadata<C, U>,
        parent: Option<TaskKey>,
        context: N::Context,
        native: N,
        claim: N::Claim,
    ) -> Self {
        Self {
            metadata,
            relations: ProcessRelations::new(parent),
            revision: TaskRevision::INITIAL,
            exiting: AtomicBool::new(false),
            context,
            native,
            claim,
            tracer: None,
            tracees: BTreeSet::new(),
            children_rusage: TaskRusage::default(),
        }
    }
    pub fn key(&self) -> TaskKey {
        self.metadata.key
    }
    pub fn metadata(&self) -> &GuestTaskMetadata<C, U> {
        &self.metadata
    }
    pub fn parent(&self) -> Option<TaskKey> {
        self.relations.parent()
    }
    pub fn children(&self) -> &BTreeSet<TaskKey> {
        self.relations.children()
    }
    pub fn revision(&self) -> TaskRevision {
        self.revision
    }
    pub fn identity(&self) -> TaskIdentity {
        self.metadata.identity
    }
    pub fn lifecycle(&self) -> TaskLifecycle {
        if self.exiting.load(Ordering::Acquire) {
            TaskLifecycle::Exiting
        } else {
            TaskLifecycle::Live
        }
    }
    pub fn context(&self) -> &N::Context {
        &self.context
    }
    pub fn context_mut(&mut self) -> &mut N::Context {
        &mut self.context
    }
    pub fn native(&self) -> &N {
        &self.native
    }
    pub fn native_mut(&mut self) -> &mut N {
        &mut self.native
    }
    pub fn children_rusage(&self) -> TaskRusage {
        self.children_rusage
    }
}
impl<C, U, N: NativeProcessCustody> WaitIdentitySource for GuestTask<C, U, N> {
    fn wait_identity(&self) -> WaitIdentity {
        WaitIdentity {
            key: self.metadata.key,
            parent: self.relations.parent(),
            tracer: self.tracer,
            group: self.metadata.identity.process_group,
            exit_signal: self.metadata.exit_signal,
        }
    }
}
impl<C, U, N: NativeProcessCustody> BirthLive for GuestTask<C, U, N> {
    type Error = N::Error;
    fn birth_lifecycle(&self) -> TaskLifecycle {
        self.lifecycle()
    }
    fn birth_revision(&self) -> TaskRevision {
        self.revision
    }
    fn birth_session(&self) -> SessionId {
        self.metadata.identity.session
    }
    fn birth_prepare_parent_revision(&self) -> Result<TaskRevision, N::Error> {
        self.native.next_revision(self.revision)
    }
    fn birth_publish_child(&mut self, child: TaskKey, revision: TaskRevision) {
        self.relations.add_child(child);
        self.revision = revision;
    }
}
impl<C, U, N: NativeProcessCustody> WaitLive for GuestTask<C, U, N> {
    type Event = N::Event;
    type Revision = TaskRevision;
    type Error = N::Error;
    fn wait_children(&self) -> Vec<TaskKey> {
        self.relations.children().iter().copied().collect()
    }
    fn wait_tracees(&self) -> Vec<TaskKey> {
        self.tracees.iter().copied().collect()
    }
    fn wait_wake_generation(&self) -> TaskWakeGeneration {
        self.native.wake_generation()
    }
    fn wait_event(&self, flags: WaitJobControl, consume: bool) -> Option<N::Event> {
        self.native.wait_event(flags, consume)
    }
    fn prepare_reap(&self) -> Result<TaskRevision, N::Error> {
        self.native.next_revision(self.revision)
    }
    fn commit_reap(&mut self, child: TaskKey, charge: TaskRusage, revision: TaskRevision) {
        self.relations.remove_child(child);
        self.children_rusage.user_time += charge.user_time;
        self.children_rusage.system_time += charge.system_time;
        self.revision = revision;
    }
}
impl<C: Copy, U, N: NativeProcessCustody> ExitLive<C> for GuestTask<C, U, N> {
    type Credit = N::Credit;
    type Error = N::Error;
    fn exit_container(&self) -> C {
        self.metadata.container
    }
    fn exit_lifecycle(&self) -> TaskLifecycle {
        self.lifecycle()
    }
    fn exit_children(&self) -> BTreeSet<TaskKey> {
        self.relations.children().clone()
    }
    fn exit_autoreaps(&self) -> bool {
        self.native.autoreaps_children()
    }
    fn exit_revision(&self) -> TaskRevision {
        self.revision
    }
    fn exit_reserve_credit(&self) -> Result<N::Credit, N::Error> {
        self.native.reserve_exit_credit(self.revision)
    }
}
impl<C: Copy, U, N: NativeProcessCustody> ExitLivePublication<C> for GuestTask<C, U, N> {
    fn exit_reparent(&mut self, parent: Option<TaskKey>) {
        self.relations.reparent(parent);
    }
    fn exit_publish_children(&mut self, children: BTreeSet<TaskKey>) {
        self.relations.publish_prepared_children(children);
    }
    fn exit_publish_credit(&mut self, participant: PreparedExitParticipant<N::Credit>) {
        self.revision = participant.publish(self.revision, |credit, current| {
            self.native.consume_exit_credit(credit, current)
        });
    }
}
impl<C: Copy, U, N: NativeProcessCustody> ExitEffectSource<C> for GuestTask<C, U, N> {
    type Member = N::Member;
    type Resources = N::Resources;
    fn exit_members(&self) -> (Vec<N::Member>, N::Resources) {
        self.native.own_members_and_resources()
    }
    fn exit_begin(&self) -> bool {
        self.exiting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}
impl<C, U, N: NativeProcessCustody> ExitNotificationSource for GuestTask<C, U, N> {
    type Target = N::SignalTarget;
    fn exit_notification_target(&self) -> N::SignalTarget {
        self.native.signal_target()
    }
}

/// Owned numeric/resource custody is never cloned with the semantic receipt.
pub struct GuestZombie<C, U, Claim> {
    pub receipt: Zombie<C, U>,
    pub claim: Claim,
}
impl<C, U, Claim> WaitZombie<C, U> for GuestZombie<C, U, Claim> {
    fn wait_zombie(&self) -> &Zombie<C, U> {
        &self.receipt
    }
}
impl<C, U, Claim> ExitZombie for GuestZombie<C, U, Claim> {
    fn exit_key(&self) -> TaskKey {
        self.receipt.key
    }
}
impl<C, U, Claim> ExitZombiePublication for GuestZombie<C, U, Claim> {
    fn exit_reparent(&mut self, parent: Option<TaskKey>) {
        self.receipt.parent = parent;
    }
}

/// Native execution/MM/file custody leaves the registry at terminal publication;
/// only the numeric claim survives in the shared zombie record.
pub struct GuestRetiring<N: NativeProcessCustody> {
    identity: WaitIdentity,
    pub context: N::Context,
    pub native: N,
}
impl<N: NativeProcessCustody> WaitIdentitySource for GuestRetiring<N> {
    fn wait_identity(&self) -> WaitIdentity {
        self.identity
    }
}
impl<N: NativeProcessCustody> ExitRetiring for GuestRetiring<N> {
    fn exit_key(&self) -> TaskKey {
        self.identity.key
    }
}

#[derive(::core::fmt::Debug)]
pub enum GuestProcessError<E> {
    InitialAlreadySeeded,
    InitialHasParent,
    Unknown(TaskId),
    Stale(TaskKey),
    AlreadyExiting(TaskId),
    Birth(BirthError<E>),
    Wait(WaitError<E>),
    Exit(ExitError<E>),
    Reservation(TaskSetError),
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum GuestProcessInvariant {
    Registry(RegistryInvariant),
    ExitCustodyLost(TaskKey),
    ExitPublicationLost(TaskKey),
    ExitReleaseLost(TaskKey),
    AbandonedExit(TaskKey),
}
pub trait GuestProcessFailure: RegistryFailure {
    fn fail_process(invariant: GuestProcessInvariant) -> !;
}
pub struct GuestRegistryFailure;
impl RegistryFailure for GuestRegistryFailure {
    fn fail(invariant: RegistryInvariant) -> ! {
        Self::fail_process(GuestProcessInvariant::Registry(invariant))
    }
}
impl GuestProcessFailure for GuestRegistryFailure {
    fn fail_process(invariant: GuestProcessInvariant) -> ! {
        #[cfg(target_os = "none")]
        {
            let _ = invariant;
            crate::substrate::sched::hw::fatal_entry_binding()
        }
        #[cfg(not(target_os = "none"))]
        carrick_fatal::carrick_fatal!(
            "el1::process_owner",
            "guest process owner invariant: {invariant:?}"
        )
    }
}

type GuestRegistry<C, U, N, F> = ProcessRegistry<
    C,
    GuestTask<C, U, N>,
    GuestZombie<C, U, <N as NativeProcessCustody>::Claim>,
    GuestRetiring<N>,
    TaskGraphReservation<<N as NativeProcessCustody>::Transaction>,
    (),
    (),
    (),
    F,
>;
type SharedGuestBirth<'a, C, U, N, F> = AdmittedProcessBirth<
    'a,
    C,
    GuestTask<C, U, N>,
    GuestZombie<C, U, <N as NativeProcessCustody>::Claim>,
    GuestRetiring<N>,
    <N as NativeProcessCustody>::Transaction,
    (),
    (),
    (),
    F,
>;
pub type GuestWaitSelection<C, U, N> =
    WaitSelection<Zombie<C, U>, <N as NativeProcessCustody>::Event>;

pub type GuestConsumedWait<C, U, N> = ConsumedWait<
    Zombie<C, U>,
    <N as NativeProcessCustody>::Event,
    GuestZombie<C, U, <N as NativeProcessCustody>::Claim>,
>;

pub struct GuestProcessOwner<C, U, N: NativeProcessCustody, F = GuestRegistryFailure> {
    registry: GuestRegistry<C, U, N, F>,
}
impl<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure> Default
    for GuestProcessOwner<C, U, N, F>
{
    fn default() -> Self {
        Self::new()
    }
}
impl<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure>
    GuestProcessOwner<C, U, N, F>
{
    pub fn new() -> Self {
        Self {
            registry: ProcessRegistry {
                epoch: 1,
                container_inits: BTreeMap::new(),
                tasks: BTreeMap::new(),
                zombies: BTreeMap::new(),
                retiring_tasks: BTreeMap::new(),
                process_groups: BTreeMap::new(),
                process_group_by_namespace: BTreeMap::new(),
                reservations: BTreeMap::new(),
                retired_threads: (),
                sessions: BTreeMap::new(),
                session_by_namespace: BTreeMap::new(),
                failure: PhantomData,
            },
        }
    }
    /// Bootstrap the one exact initial task and its group/session through the
    /// shared registry's identity indexes. No native identity is reconstructed.
    pub fn seed_initial(
        &mut self,
        task: GuestTask<C, U, N>,
    ) -> Result<(), GuestProcessError<N::Error>> {
        if !self.registry.container_inits.is_empty()
            || !self.registry.tasks.is_empty()
            || !self.registry.zombies.is_empty()
            || !self.registry.retiring_tasks.is_empty()
        {
            return Err(GuestProcessError::InitialAlreadySeeded);
        }
        if task.relations.parent().is_some() {
            return Err(GuestProcessError::InitialHasParent);
        }
        let key = task.metadata.key;
        let container = task.metadata.container;
        let identity = task.metadata.identity;
        self.registry.publish_process_group(
            identity.process_group,
            ProcessGroupRecord {
                object: (),
                members: BTreeSet::from([key]),
                container,
                namespace_id: task.metadata.namespace_process_group,
            },
        );
        self.registry.publish_session(
            identity.session,
            SessionRecord {
                object: (),
                process_groups: BTreeSet::from([identity.process_group]),
                container,
                namespace_id: task.metadata.namespace_session,
            },
        );
        self.registry.container_inits.insert(container, key);
        self.registry.tasks.insert(key.id, task);
        Ok(())
    }
    pub fn task(&self, key: TaskKey) -> Result<&GuestTask<C, U, N>, GuestProcessError<N::Error>> {
        let task = self
            .registry
            .tasks
            .get(&key.id)
            .ok_or(GuestProcessError::Unknown(key.id))?;
        if task.metadata.key != key {
            return Err(GuestProcessError::Stale(key));
        }
        if task.lifecycle() != TaskLifecycle::Live {
            return Err(GuestProcessError::AlreadyExiting(key.id));
        }
        Ok(task)
    }
    pub fn task_mut(
        &mut self,
        key: TaskKey,
    ) -> Result<&mut GuestTask<C, U, N>, GuestProcessError<N::Error>> {
        let task = self
            .registry
            .tasks
            .get_mut(&key.id)
            .ok_or(GuestProcessError::Unknown(key.id))?;
        if task.metadata.key != key {
            return Err(GuestProcessError::Stale(key));
        }
        if task.lifecycle() != TaskLifecycle::Live {
            return Err(GuestProcessError::AlreadyExiting(key.id));
        }
        Ok(task)
    }
    pub fn namespace_child_key(
        &self,
        caller: TaskKey,
        visible_pid: u32,
    ) -> Result<Option<TaskKey>, GuestProcessError<N::Error>> {
        let parent = self.task(caller)?;
        Ok(parent.children().iter().copied().find(|key| {
            self.registry.tasks.get(&key.id).is_some_and(|row| {
                row.key() == *key
                    && row.parent() == Some(caller)
                    && row.metadata.container == parent.metadata.container
                    && row.metadata.namespace_pid == visible_pid
            }) || self.registry.zombies.get(&key.id).is_some_and(|row| {
                row.receipt.key == *key
                    && row.receipt.parent == Some(caller)
                    && row.receipt.container == parent.metadata.container
                    && row.receipt.namespace_pid == visible_pid
            })
        }))
    }
    pub fn capture_parent(
        &self,
        key: TaskKey,
    ) -> Result<BirthSnapshot, GuestProcessError<N::Error>> {
        let task = self.task(key)?;
        Ok(BirthSnapshot {
            key: task.metadata.key,
            revision: task.revision,
        })
    }
    /// Borrow the unpublished child rather than consume its resource custody on
    /// refusal. Native MM preparation remains caller-owned and rollback-capable
    /// until this shared guard-retained admission succeeds.
    pub fn admit_child(
        &mut self,
        caller: BirthSnapshot,
        parent: BirthSnapshot,
        child: &GuestTask<C, U, N>,
        attachment: BirthAttachment,
        permit: Option<&ReservedTaskSet<N::Transaction>>,
    ) -> Result<GuestChildAdmission<'_, C, U, N, F>, GuestProcessError<N::Error>> {
        let admission = self
            .registry
            .admit_process_birth(
                caller,
                parent,
                child.wait_identity(),
                child.metadata.identity.session,
                attachment,
                permit,
            )
            .map_err(GuestProcessError::Birth)?;
        Ok(GuestChildAdmission { admission })
    }
    /// Resource reservation only. Snapshot validation/publication remains in
    /// the shared birth admission; returned exact permits can be explicitly
    /// released/rolled back by native preparation's existing lifetime owner.
    pub fn reserve_birth(
        &mut self,
        caller: BirthSnapshot,
        parent: BirthSnapshot,
        transaction: N::Transaction,
    ) -> Result<ReservedTaskSet<N::Transaction>, GuestProcessError<N::Error>> {
        self.registry
            .reserve_task_set(alloc::vec![caller.key.id, parent.key.id], transaction)
            .map_err(GuestProcessError::Reservation)
    }
    pub fn release_birth(
        &mut self,
        permit: &ReservedTaskSet<N::Transaction>,
    ) -> Result<ReleasedTaskSet<N::Transaction>, GuestProcessError<N::Error>> {
        self.registry
            .release_task_set(permit)
            .map_err(GuestProcessError::Reservation)
    }
    pub fn rollback_birth(&mut self, permit: &ReservedTaskSet<N::Transaction>) -> bool {
        self.registry.rollback_task_set(permit)
    }
    pub fn precheck_wait(
        &self,
        caller: TaskKey,
        query: WaitQuery,
    ) -> Result<WaitReadiness, GuestProcessError<N::Error>> {
        self.task(caller)?;
        self.registry
            .admit_wait(caller.id)
            .map_err(GuestProcessError::Wait)?;
        self.registry
            .precheck_wait::<U>(caller.id, query)
            .map_err(GuestProcessError::Wait)
    }
    pub fn scan_wait(
        &self,
        caller: TaskKey,
        query: WaitQuery,
    ) -> Result<GuestWaitSelection<C, U, N>, GuestProcessError<N::Error>> {
        self.task(caller)?;
        self.registry
            .scan_wait(caller.id, query)
            .map_err(GuestProcessError::Wait)
    }
    pub fn consume_wait(
        &mut self,
        caller: TaskKey,
        query: WaitQuery,
    ) -> Result<GuestConsumedWait<C, U, N>, GuestProcessError<N::Error>> {
        self.task(caller)?;
        self.registry
            .consume_wait(caller.id, query)
            .map_err(GuestProcessError::Wait)
    }
    pub fn prepare_exit(
        &mut self,
        task: TaskKey,
        explicit_adopter: Option<TaskKey>,
    ) -> Result<GuestExitPreparation<'_, C, U, N, F>, GuestProcessError<N::Error>> {
        let topology = self
            .registry
            .prepare_exit_topology(task, explicit_adopter)
            .map_err(GuestProcessError::Exit)?;
        Ok(GuestExitPreparation {
            registry: &mut self.registry,
            task,
            topology,
        })
    }
    /// Retain an exact shared parent target after exact member cancellation.
    /// The caller drops its enclosing graph guard before target.prepare().
    pub fn select_exit_parent(
        &self,
        permit: &ExitParentPermit,
    ) -> Option<ExitParentTarget<N::SignalTarget>> {
        self.registry.select_exit_parent(permit)
    }
}

#[must_use = "publish admitted custody or release admission without graph publication"]
pub struct GuestChildAdmission<'a, C, U, N: NativeProcessCustody, F> {
    admission: SharedGuestBirth<'a, C, U, N, F>,
}
impl<C: Copy + Ord, U, N: NativeProcessCustody, F: RegistryFailure>
    GuestChildAdmission<'_, C, U, N, F>
{
    pub fn publish(self, child: GuestTask<C, U, N>) {
        self.admission.publish(child);
    }
}

/// Shared topology preparation holds registry custody; dropping before reserve
/// returns every owned participant credit without changing the graph.
#[must_use = "reserve the prepared exit or release its unchanged topology admission"]
pub struct GuestExitPreparation<
    'a,
    C: Copy + Ord,
    U: Clone,
    N: NativeProcessCustody,
    F: GuestProcessFailure,
> {
    registry: &'a mut GuestRegistry<C, U, N, F>,
    task: TaskKey,
    topology: PreparedExitTopology<N::Credit>,
}
impl<'a, C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure>
    GuestExitPreparation<'a, C, U, N, F>
{
    pub fn reserve(
        self,
        transaction: N::Transaction,
    ) -> Result<GuestReservedExit<'a, C, U, N, F>, GuestProcessError<N::Error>> {
        let permit = self
            .registry
            .reserve_exit_task_set(&self.topology, transaction)
            .map_err(GuestProcessError::Reservation)?;
        Ok(GuestReservedExit {
            registry: Some(self.registry),
            task: self.task,
            topology: Some(self.topology),
            permit: Some(permit),
        })
    }
}

/// A not-yet-begun exit automatically releases its exact reservation on drop.
/// The retained registry borrow makes rebinding/foreign rollback impossible.
#[must_use = "begin the admitted exit or drop it to roll back its reservation"]
pub struct GuestReservedExit<
    'a,
    C: Copy + Ord,
    U: Clone,
    N: NativeProcessCustody,
    F: GuestProcessFailure,
> {
    registry: Option<&'a mut GuestRegistry<C, U, N, F>>,
    task: TaskKey,
    topology: Option<PreparedExitTopology<N::Credit>>,
    permit: Option<ReservedTaskSet<N::Transaction>>,
}
impl<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure> Drop
    for GuestReservedExit<'_, C, U, N, F>
{
    fn drop(&mut self) {
        if let (Some(registry), Some(permit)) = (self.registry.as_deref_mut(), self.permit.as_ref())
        {
            registry.rollback_task_set(permit);
        }
    }
}
impl<'a, C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure>
    GuestReservedExit<'a, C, U, N, F>
{
    /// Shared begin validates exact members and reservations before marking the
    /// task exiting. Every following graph operation uses the retained guard.
    pub fn begin(
        mut self,
        status: LinuxWaitStatus,
    ) -> Result<GuestPendingExit<'a, C, U, N, F>, GuestProcessError<N::Error>> {
        let registry = self
            .registry
            .as_deref_mut()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let topology = self
            .topology
            .as_mut()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let permit = self
            .permit
            .as_ref()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let record = registry
            .tasks
            .get(&self.task.id)
            .ok_or(GuestProcessError::Unknown(self.task.id))?;
        let identity = record.wait_identity();
        let observation = Zombie {
            key: record.metadata.key,
            namespace_pid: record.metadata.namespace_pid,
            container: record.metadata.container,
            parent: record.relations.parent(),
            process_group: record.metadata.identity.process_group,
            session: record.metadata.identity.session,
            namespace_process_group: record.metadata.namespace_process_group,
            namespace_session: record.metadata.namespace_session,
            status,
            ruid: record.metadata.ruid.clone(),
            euid: record.metadata.euid.clone(),
            rusage: record.native.own_rusage(),
            children_rusage: record.children_rusage,
            exit_signal: record.metadata.exit_signal,
            diagnostic_name: record.metadata.diagnostic_name.clone(),
        };
        let effects = registry
            .begin_exit_effects(self.task, topology, permit)
            .map_err(GuestProcessError::Exit)?;
        let record = registry
            .tasks
            .remove(&self.task.id)
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        registry.publish_exit_topology(topology);
        registry.retiring_tasks.insert(
            self.task.id,
            GuestRetiring {
                identity,
                context: record.context,
                native: record.native,
            },
        );
        let receipt = GuestZombie {
            receipt: observation,
            claim: record.claim,
        };
        // Taking every component disarms the not-begun reservation rollback.
        let registry = self
            .registry
            .take()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let topology = self
            .topology
            .take()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let permit = self
            .permit
            .take()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        Ok(GuestPendingExit {
            registry: Some(registry),
            task: self.task,
            topology: Some(topology),
            permit: Some(permit),
            receipt: Some(receipt),
            effects: Some(effects),
        })
    }
}

/// Irreversible exit custody keeps the original topology, exact reservation,
/// numeric claim and effects together; callers cannot cross-feed a new plan.
/// Abandonment fails closed, rather than release a claim or leave a retiring row.
#[must_use = "publish and release irreversible exit custody before native transfer"]
pub struct GuestPendingExit<
    'a,
    C: Copy + Ord,
    U: Clone,
    N: NativeProcessCustody,
    F: GuestProcessFailure,
> {
    registry: Option<&'a mut GuestRegistry<C, U, N, F>>,
    task: TaskKey,
    topology: Option<PreparedExitTopology<N::Credit>>,
    permit: Option<ReservedTaskSet<N::Transaction>>,
    receipt: Option<GuestZombie<C, U, N::Claim>>,
    effects: Option<PendingExitEffects<N::Member, N::Resources, N::Transaction>>,
}
impl<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure> Drop
    for GuestPendingExit<'_, C, U, N, F>
{
    fn drop(&mut self) {
        if self.registry.is_some() {
            F::fail_process(GuestProcessInvariant::AbandonedExit(self.task));
        }
    }
}
impl<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure>
    GuestPendingExit<'_, C, U, N, F>
{
    pub fn take_resources(&mut self) -> Option<N::Resources> {
        self.effects
            .as_mut()
            .and_then(PendingExitEffects::take_resources)
    }
    /// Terminal receipt and exact release are shared decisions. Native member
    /// cancellation is returned as ReadyExitEffects and runs outside the guard.
    pub fn publish(mut self) -> GuestPublishedExit<C, U, N> {
        let registry = self
            .registry
            .as_deref_mut()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let topology = self
            .topology
            .as_ref()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let permit = self
            .permit
            .as_ref()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let receipt = self
            .receipt
            .take()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)));
        let identity = (receipt.receipt.process_group, receipt.receipt.session);
        let publication = registry
            .publish_exit_receipt(self.task, topology, receipt, identity.0, identity.1)
            .unwrap_or_else(|_| {
                F::fail_process(GuestProcessInvariant::ExitPublicationLost(self.task))
            });
        let released = registry
            .release_task_set(permit)
            .unwrap_or_else(|_| F::fail_process(GuestProcessInvariant::ExitReleaseLost(self.task)));
        let effects = self
            .effects
            .take()
            .unwrap_or_else(|| F::fail_process(GuestProcessInvariant::ExitCustodyLost(self.task)))
            .after_release(released)
            .unwrap_or_else(|_| F::fail_process(GuestProcessInvariant::ExitReleaseLost(self.task)));
        // Successful receipt/release disarms irreversible-custody abandonment.
        self.registry = None;
        GuestPublishedExit {
            retiring: publication.retiring,
            autoreaped_receipt: publication.autoreaped_receipt,
            effects,
        }
    }
}
pub struct GuestPublishedExit<C, U, N: NativeProcessCustody> {
    pub retiring: GuestRetiring<N>,
    pub autoreaped_receipt: Option<GuestZombie<C, U, N::Claim>>,
    pub effects: ReadyExitEffects<N::Member>,
}

#[cfg(test)]
#[path = "process_owner_tests.rs"]
mod tests;
