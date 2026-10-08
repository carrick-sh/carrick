//! Native process custody over the shared guest owner and compact zone.
//! Root admission adopts the existing execution incarnation as a local process
//! incarnation; it does not import a host TaskSerial or launcher credentials.
extern crate alloc;
use super::{
    native_process_custody::{ProcessResources, ProcessWake, RetainedProcessCustody},
    native_process_entry::{self, ForkTryError, PreparedFork, WaitWork},
    native_process_signals::{NativeExitSignals, NativeProcessSignals, NativeSignalError},
    process_owner::*,
};
use crate::lock::SpinLock;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, EntryHandoffReceipt, EntryIdentity, EntryRef, ExecutionBinding,
    Lifecycle, ThreadControlSlot, ThreadLifecyclePage,
};
use carrick_guest_arch::{AddressContext, MmGeneration, RootGpa, UserVa};
use carrick_personality_linux::{
    abi::entry::SyscallResult,
    lifecycle::{LifecycleOutcome, LinuxWaitOptions, ProcessNative, ProcessWaitPid},
};
use carrick_sched_core::process::{
    ChildExitSignal, LinuxWaitStatus, TaskId, TaskIdentity, TaskKey, TaskRusage, TaskSerial,
    WaitChildClass, WaitTarget,
};
use carrick_sched_core::process::{
    birth::BirthAttachment,
    exit::ExitMember,
    identity_allocator::{
        ClaimKind, InternalIdentity, NamespaceState, SerialAllocator, VisibleIdentity,
        VisibleNamespace,
    },
    wait::{WaitJobControl, WaitPrecheck, WaitQuery, WaitSelection},
};
use carrick_sched_core::{
    BoundedSpin, Handback, ParkedContextWords, RecordRef, ThreadIdentity, WakeEffects, Waker,
    ZoneTables,
};
use core::{
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::Ordering,
};
const LOCK_SPINS: u32 = 100_000;
/// Retained private task metadata. Slot zero belongs to a host-admitted leader;
/// shared pool births use the exact entry index plus one, including fork leaders.
pub struct NativeLifecycleResources<'a> {
    pub page: &'a ThreadLifecyclePage,
    pub controls: &'a [ThreadControlSlot],
}
impl<'a> NativeLifecycleResources<'a> {
    pub fn born_slot(&self, entry: EntryRef) -> Option<&'a ThreadControlSlot> {
        self.controls.get(entry.index().checked_add(1)?)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessError {
    Invalid,
    Stale,
    Exhausted,
    Fault,
    Unsupported,
    Busy,
    Quarantined,
    NoChild,
}
impl NativeProcessError {
    pub fn errno(self) -> i64 {
        match self {
            Self::Invalid | Self::Stale => -22,
            Self::Exhausted | Self::Busy => -11,
            Self::Fault => -14,
            Self::Unsupported => -38,
            Self::Quarantined => -5,
            Self::NoChild => -10,
        }
    }
}
/// Physical crossings are outside graph guards. commit_mm is only the final
/// guest-core root publication; preparation has already performed descriptor
/// work. A failed settlement retains the closed child and never queues it.
pub trait NativeProcessService<'a> {
    type Mm: Clone;
    type PreparedMm;
    type Born;
    fn prepare_mm(
        &mut self,
        parent: &Self::Mm,
        words: ParkedContextWords,
        child: MmGeneration,
    ) -> Result<Self::PreparedMm, NativeProcessError>;
    fn prepared_mm(&self, prepared: &Self::PreparedMm) -> Self::Mm;
    fn prepared_context(&self, prepared: &Self::PreparedMm) -> AddressContext<RootGpa>;
    fn child_lifecycle(&self, prepared: &Self::PreparedMm) -> NativeLifecycleResources<'a>;
    fn commit_mm(
        &mut self,
        prepared: Self::PreparedMm,
    ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)>;
    fn abort_mm(
        &mut self,
        prepared: Self::PreparedMm,
    ) -> Result<(), (NativeProcessError, Self::PreparedMm)>;
    fn settle_mm(&mut self, born: Self::Born) -> Result<(), (NativeProcessError, Self::Born)>;
    fn copy_status(
        &mut self,
        parent: &Self::Mm,
        address: UserVa,
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError>;
    fn quarantine_prepared(&mut self, prepared: Self::PreparedMm);
    /// Preserve both guest admission and MM preparation if rollback refuses.
    fn quarantine_fork(&mut self, prepared: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm>);
    fn quarantine_born(&mut self, born: Self::Born);
    fn retire_mm(&mut self, mm: Self::Mm);
    fn wake_effects(&mut self, effects: WakeEffects);
}
pub struct NativeClaim {
    namespace: Arc<SpinLock<NamespaceState>>,
    claims: Vec<(InternalIdentity, ClaimKind)>,
}
impl Drop for NativeClaim {
    fn drop(&mut self) {
        let mut ns = self.namespace.lock();
        for &(number, kind) in &self.claims {
            ns.release(number, kind);
        }
    }
}
struct WaitChannel {
    generation: ProcessWake,
    mm: u64,
}
impl WaitChannel {
    fn address(this: &Arc<Self>) -> u64 {
        Arc::as_ptr(this) as u64
    }
}
pub struct NativeMember<'a> {
    key: TaskKey,
    zone: &'a ZoneTables<ParkedContextWords>,
    record: RecordRef,
}
impl ExitMember for NativeMember<'_> {
    fn exit_task(&self) -> TaskKey {
        self.key
    }
}
pub struct NativeResources<'a, M> {
    key: TaskKey,
    zone: &'a ZoneTables<ParkedContextWords>,
    record: RecordRef,
    control: &'a ThreadControlSlot,
    page: &'a ThreadLifecyclePage,
    mm: M,
    address: AddressContext<RootGpa>,
    signals: NativeProcessSignals<()>,
    _thread_claim: NativeClaim,
    channel: Option<Arc<WaitChannel>>,
    usage: TaskRusage,
}
pub type NativeForkPreparation<'a, M, P> =
    PreparedFork<(), (), RetainedProcessCustody<NativeResources<'a, M>>, P>;
impl<'a, M: Clone> ProcessResources for NativeResources<'a, M> {
    type Claim = NativeClaim;
    type Event = ();
    type Transaction = NonZeroU64;
    type Member = NativeMember<'a>;
    type Resources = M;
    type SignalTarget = NativeExitSignals<(), &'a ThreadControlSlot>;
    fn wait_event(&self, _: WaitJobControl, _: bool) -> Option<()> {
        None
    }
    fn own_members_and_resources(&self) -> (Vec<Self::Member>, M) {
        (
            vec![NativeMember {
                key: self.key,
                zone: self.zone,
                record: self.record,
            }],
            self.mm.clone(),
        )
    }
    fn signal_target(&self) -> Self::SignalTarget {
        self.signals.exit_source(self.control)
    }
    fn autoreaps_children(&self) -> bool {
        self.signals.autoreaps_children()
    }
    fn own_rusage(&self) -> TaskRusage {
        self.usage
    }
}
type Custody<'a, M> = RetainedProcessCustody<NativeResources<'a, M>>;
type Owner<'a, M> = GuestProcessOwner<(), (), Custody<'a, M>>;
struct PendingWait {
    caller: TaskKey,
    query: WaitQuery,
    status: UserVa,
    precheck: WaitPrecheck,
    channel: Arc<WaitChannel>,
}
struct Graph<'a, M: Clone> {
    owner: Owner<'a, M>,
    root_key: TaskKey,
    namespace: Arc<SpinLock<NamespaceState>>,
    visible_namespace: VisibleNamespace,
    serials: SerialAllocator,
    pending: BTreeMap<TaskKey, PendingWait>,
    _root_roles: NativeClaim,
}
pub struct NativeProcessRuntime<'a, M: Clone> {
    graph: SpinLock<Graph<'a, M>>,
    zone: &'a ZoneTables<ParkedContextWords>,
}
pub struct NativeRecordBinding<M> {
    pub key: TaskKey,
    pub visible_pid: u32,
    pub mm: M,
    pub address: AddressContext<RootGpa>,
    pub words: ParkedContextWords,
}
fn custody<'a, M: Clone>(resources: NativeResources<'a, M>) -> Custody<'a, M> {
    let mut custody = RetainedProcessCustody::new(resources);
    let channel = Arc::new(WaitChannel {
        generation: custody.wake(),
        mm: custody.resources().record_identity_mm(),
    });
    custody.resources_mut().channel = Some(channel);
    custody
}
impl<M> NativeResources<'_, M> {
    fn record_identity_mm(&self) -> u64 {
        self.zone.record(self.record.id).identity().mm
    }
}
impl<'a, M: Clone> NativeProcessRuntime<'a, M> {
    pub fn zone(&self) -> &'a ZoneTables<ParkedContextWords> {
        self.zone
    }
    #[allow(clippy::too_many_arguments)]
    pub fn admit_fresh_root(
        source: BornInZoneSource<'a, ParkedContextWords>,
        current: &'a CurrentTask,
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
        mm: M,
        address: AddressContext<RootGpa>,
        words: ParkedContextWords,
    ) -> Result<Self, NativeProcessError> {
        let binding = super::common_entry::execution_binding(current);
        let record = source
            .zone
            .slot(source.slot)
            .current()
            .or_else(|| source.zone.slot(source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        carrick_core::entry::prepare_handoff(binding, source, record)
            .ok_or(NativeProcessError::Stale)?;
        let identity = source.zone.record(record).identity();
        let visible = current
            .visible_pid()
            .and_then(NonZeroU32::new)
            .ok_or(NativeProcessError::Invalid)?;
        let id = i32::try_from(binding.task.raw())
            .ok()
            .and_then(|id| TaskId::from_abi_positive(id).ok())
            .ok_or(NativeProcessError::Invalid)?;
        let key = TaskKey {
            id,
            serial: TaskSerial::from_raw_u64(binding.generation.raw())
                .ok_or(NativeProcessError::Invalid)?,
        };
        if !words.authenticates(address)
            || address.mm.raw().get() != binding.mm.raw()
            || identity.lifecycle_page != page as *const _ as u64
            || identity.control_slot != control as *const _ as u64
            || current.metadata.lifecycle_page.load(Ordering::Acquire) != identity.lifecycle_page
            || current.metadata.control_slot.load(Ordering::Acquire) != identity.control_slot
        {
            return Err(NativeProcessError::Stale);
        }
        let index = source
            .zone
            .spaces
            .find(binding.mm.raw())
            .ok_or(NativeProcessError::Stale)?;
        if source
            .zone
            .spaces
            .grant(index, binding.mm.raw())
            .is_none_or(|grant| grant.ttbr0 != address.root.address().raw())
        {
            return Err(NativeProcessError::Stale);
        }
        // Fresh native leader only: normalize the retained bootstrap's
        // temporary count of two through the checked membership transition.
        match page.live() {
            1 => {}
            2 => {
                page.release_live(1)
                    .map_err(|_| NativeProcessError::Stale)?;
            }
            _ => return Err(NativeProcessError::Invalid),
        }
        let ns = Arc::new(SpinLock::new(NamespaceState::new(1, i32::MAX, id.raw())));
        let visible_namespace = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let (task_claim, thread_claim, root_roles) = {
            let mut n = ns.lock();
            let number = n
                .reserve_exact(id.raw(), ClaimKind::Task)
                .map_err(|_| NativeProcessError::Exhausted)?;
            n.claim_related(id.raw(), ClaimKind::Thread)
                .map_err(|_| NativeProcessError::Exhausted)?;
            n.claim_related(id.raw(), ClaimKind::ProcessGroup)
                .map_err(|_| NativeProcessError::Exhausted)?;
            n.claim_related(id.raw(), ClaimKind::Session)
                .map_err(|_| NativeProcessError::Exhausted)?;
            n.advance_visible_past(
                visible_namespace,
                VisibleIdentity::from_existing_member(visible),
            )
            .ok_or(NativeProcessError::Exhausted)?;
            (
                NativeClaim {
                    namespace: ns.clone(),
                    claims: vec![(number, ClaimKind::Task)],
                },
                NativeClaim {
                    namespace: ns.clone(),
                    claims: vec![(number, ClaimKind::Thread)],
                },
                NativeClaim {
                    namespace: ns.clone(),
                    claims: vec![
                        (number, ClaimKind::ProcessGroup),
                        (number, ClaimKind::Session),
                    ],
                },
            )
        };
        let serials = SerialAllocator::new();
        serials
            .advance_past(
                NonZeroU64::new(
                    binding
                        .generation
                        .raw()
                        .max(binding.thread_generation.raw())
                        .max(binding.mm.raw()),
                )
                .ok_or(NativeProcessError::Invalid)?,
            )
            .ok_or(NativeProcessError::Exhausted)?;
        let resources = NativeResources {
            key,
            zone: source.zone,
            record: source.zone.record_ref(record),
            control,
            page,
            mm,
            address,
            signals: NativeProcessSignals::fresh_root(key),
            _thread_claim: thread_claim,
            channel: None,
            usage: TaskRusage::default(),
        };
        let mut owner = Owner::new();
        owner
            .seed_initial(GuestTask::new(
                GuestTaskMetadata {
                    key,
                    container: (),
                    namespace_pid: visible.get(),
                    identity: TaskIdentity::led_by(id),
                    namespace_process_group: visible.get(),
                    namespace_session: visible.get(),
                    ruid: (),
                    euid: (),
                    exit_signal: ChildExitSignal::SIGCHLD,
                    diagnostic_name: String::from("native-root"),
                },
                None,
                words,
                custody(resources),
                task_claim,
            ))
            .map_err(|_| NativeProcessError::Invalid)?;
        Ok(Self {
            graph: SpinLock::new(Graph {
                owner,
                root_key: key,
                namespace: ns,
                visible_namespace,
                serials,
                pending: BTreeMap::new(),
                _root_roles: root_roles,
            }),
            zone: source.zone,
        })
    }
    pub fn enter<'r, S: NativeProcessService<'a, Mm = M>>(
        &'r self,
        source: BornInZoneSource<'a, ParkedContextWords>,
        current: &'a CurrentTask,
        words: ParkedContextWords,
        service: &'r mut S,
    ) -> Result<NativeProcessEntry<'r, 'a, M, S>, NativeProcessError> {
        if !core::ptr::eq(source.zone, self.zone) {
            return Err(NativeProcessError::Stale);
        }
        let binding = super::common_entry::execution_binding(current);
        let record = source
            .zone
            .slot(source.slot)
            .current()
            .or_else(|| source.zone.slot(source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        carrick_core::entry::prepare_handoff(binding, source, record)
            .ok_or(NativeProcessError::Stale)?;
        let key = TaskKey {
            id: TaskId::from_abi_positive(
                i32::try_from(binding.task.raw()).map_err(|_| NativeProcessError::Invalid)?,
            )
            .map_err(|_| NativeProcessError::Invalid)?,
            serial: TaskSerial::from_raw_u64(binding.generation.raw())
                .ok_or(NativeProcessError::Invalid)?,
        };
        let mut graph = self.graph.lock();
        let row = graph
            .owner
            .task_mut(key)
            .map_err(|_| NativeProcessError::Stale)?;
        if row.native().resources().record != source.zone.record_ref(record)
            || !words.authenticates(row.native().resources().address)
        {
            return Err(NativeProcessError::Stale);
        }
        *row.context_mut() = words;
        drop(graph);
        Ok(NativeProcessEntry {
            runtime: self,
            source,
            binding,
            key,
            words,
            service,
            handoff: None,
            root_exit: None,
        })
    }
    pub fn namespace_child_key(&self, caller: TaskKey, visible: u32) -> Option<TaskKey> {
        self.graph
            .lock()
            .owner
            .namespace_child_key(caller, visible)
            .ok()
            .flatten()
    }
    /// Resolve the sole owned live row from an authenticated scheduler record.
    pub fn record_binding(&self, record: RecordRef) -> Option<NativeRecordBinding<M>> {
        let identity = self.zone.record(record.id).identity();
        let key = TaskKey {
            id: TaskId::from_abi_positive(i32::try_from(identity.tid).ok()?).ok()?,
            serial: TaskSerial::from_raw_u64(identity.generation)?,
        };
        let graph = self.graph.lock();
        let row = graph.owner.task(key).ok()?;
        let resources = row.native().resources();
        (resources.record == record).then(|| NativeRecordBinding {
            key,
            visible_pid: row.metadata().namespace_pid,
            mm: resources.mm.clone(),
            address: resources.address,
            words: *row.context(),
        })
    }
}
pub struct NativeProcessEntry<'r, 'a, M: Clone, S: NativeProcessService<'a, Mm = M>> {
    runtime: &'r NativeProcessRuntime<'a, M>,
    source: BornInZoneSource<'a, ParkedContextWords>,
    binding: ExecutionBinding,
    key: TaskKey,
    words: ParkedContextWords,
    service: &'r mut S,
    handoff: Option<EntryHandoffReceipt<ParkedContextWords>>,
    root_exit: Option<LinuxWaitStatus>,
}
fn returned(value: i64) -> LifecycleOutcome {
    LifecycleOutcome::Returned {
        result: SyscallResult::new(value),
        work: false,
    }
}
impl<'a, M: Clone, S: NativeProcessService<'a, Mm = M>> NativeProcessEntry<'_, 'a, M, S> {
    pub fn take_root_exit(&mut self) -> Option<LinuxWaitStatus> {
        self.root_exit.take()
    }
    pub fn is_root_process(&self) -> bool {
        let graph = self.runtime.graph.lock();
        self.key == graph.root_key
            && graph
                .owner
                .task(self.key)
                .is_ok_and(|row| row.parent().is_none())
    }
    fn fail(&self, error: NativeProcessError) -> LifecycleOutcome {
        returned(error.errno())
    }
    fn query(
        &self,
        pid: ProcessWaitPid,
        options: LinuxWaitOptions,
    ) -> Result<WaitQuery, NativeProcessError> {
        if options.bits() & !LinuxWaitOptions::WAIT4_SUPPORTED.bits() != 0 {
            return Err(NativeProcessError::Invalid);
        }
        if options.intersects(LinuxWaitOptions::WUNTRACED | LinuxWaitOptions::WCONTINUED) {
            return Err(NativeProcessError::Unsupported);
        }
        let graph = self.runtime.graph.lock();
        let row = graph
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?;
        let target = match pid.raw() {
            -1 => WaitTarget::Any,
            0 => WaitTarget::ProcessGroup(row.identity().process_group),
            p if p > 0 => WaitTarget::Exact(
                graph
                    .owner
                    .namespace_child_key(self.key, p as u32)
                    .map_err(|_| NativeProcessError::Stale)?
                    .ok_or(NativeProcessError::NoChild)?,
            ),
            p => {
                if p.unsigned_abs() != row.metadata().namespace_process_group {
                    return Err(NativeProcessError::NoChild);
                };
                WaitTarget::ProcessGroup(row.identity().process_group)
            }
        };
        Ok(WaitQuery {
            target,
            class: WaitChildClass::from_wait_options(options),
            job_control: WaitJobControl::NONE,
        })
    }
    fn wait_query(
        &mut self,
        query: WaitQuery,
        status: UserVa,
        nohang: bool,
    ) -> Result<LifecycleOutcome, NativeProcessError> {
        loop {
            let (selection, mm, channel) = {
                let graph = self.runtime.graph.lock();
                let row = graph
                    .owner
                    .task(self.key)
                    .map_err(|_| NativeProcessError::Stale)?;
                let mm = row.native().resources().mm.clone();
                let channel = row
                    .native()
                    .resources()
                    .channel
                    .as_ref()
                    .ok_or(NativeProcessError::Stale)?
                    .clone();
                let selected = native_process_entry::scan_wait(&graph.owner, self.key, query)
                    .map_err(|_| NativeProcessError::Busy)?;
                (selected, mm, channel)
            };
            match selection {
                WaitWork::Status(copy) => {
                    let copied = copy.copy_with(|zombie| {
                        if status.raw() == 0 {
                            Ok(())
                        } else {
                            self.service.copy_status(&mm, status, zombie.status)
                        }
                    })?;
                    let consumed = {
                        let mut graph = self.runtime.graph.lock();
                        copied
                            .consume(&mut graph.owner)
                            .map_err(|_| NativeProcessError::Busy)?
                    };
                    let result = match &consumed.selection {
                        WaitSelection::Exited(zombie) => i64::from(zombie.namespace_pid),
                        _ => return Err(NativeProcessError::NoChild),
                    };
                    drop(consumed);
                    return Ok(returned(result));
                }
                WaitWork::Other(WaitSelection::NoChild) => return Err(NativeProcessError::NoChild),
                WaitWork::Other(WaitSelection::Event(_) | WaitSelection::Exited(_)) => {
                    return Err(NativeProcessError::Unsupported);
                }
                WaitWork::Other(WaitSelection::StillRunning(precheck)) => {
                    if nohang {
                        return Ok(returned(0));
                    }
                    let zone = self.source.zone;
                    let record = zone
                        .slot(self.source.slot)
                        .current()
                        .or_else(|| zone.slot(self.source.slot).host_record())
                        .ok_or(NativeProcessError::Stale)?;
                    let start =
                        carrick_core::entry::prepare_handoff(self.binding, self.source, record)
                            .ok_or(NativeProcessError::Stale)?;
                    let address = WaitChannel::address(&channel);
                    let guard = zone
                        .lock(
                            ZoneTables::<ParkedContextWords>::bucket_of_with_context(
                                channel.mm, address,
                            ),
                            &BoundedSpin(LOCK_SPINS),
                        )
                        .ok_or(NativeProcessError::Busy)?;
                    // A changed generation denotes an actual child publication.
                    // Reclassify that event; no clock, sleep or polling is used.
                    if channel.generation.generation() != precheck.wake_generation() {
                        drop(guard);
                        continue;
                    }
                    {
                        let graph = self.runtime.graph.lock();
                        if graph.pending.contains_key(&self.key) {
                            return Err(NativeProcessError::Busy);
                        }
                    }
                    let sequence = zone.next_seq(record);
                    zone.enqueue(&guard, record, sequence, channel.mm, address, u32::MAX, 0)
                        .map_err(|_| NativeProcessError::Exhausted)?;
                    // SAFETY: authenticated current ownership remains held until
                    // this exact record's park CAS below, under its bucket guard.
                    unsafe { *zone.record(record).ctx_mut() = self.words };
                    self.runtime.graph.lock().pending.insert(
                        self.key,
                        PendingWait {
                            caller: self.key,
                            query,
                            status,
                            precheck,
                            channel,
                        },
                    );
                    let receipt = carrick_core::entry::publish_handoff_park(
                        start,
                        &guard,
                        carrick_el1_abi::EntryRecordGeneration(sequence),
                    );
                    if receipt.is_none() {
                        self.runtime.graph.lock().pending.remove(&self.key);
                        return Err(NativeProcessError::Busy);
                    }
                    drop(guard);
                    zone.clear_current(self.source.slot);
                    self.handoff = receipt;
                    return Ok(LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        result: SyscallResult::new(0),
                    });
                }
            }
        }
    }
    /// The execution lane calls this before returning a woken saved syscall to
    /// userspace. It consumes the retained wait operation instead of replaying it.
    pub fn resume_pending_wait(&mut self) -> Option<LifecycleOutcome> {
        let pending = self.runtime.graph.lock().pending.remove(&self.key)?;
        if pending.caller != self.key
            || pending.channel.generation.generation() == pending.precheck.wake_generation()
        {
            self.runtime.graph.lock().pending.insert(self.key, pending);
            return Some(self.fail(NativeProcessError::Stale));
        }
        Some(
            match self.wait_query(pending.query, pending.status, false) {
                Ok(outcome) => outcome,
                Err(error) => self.fail(error),
            },
        )
    }
    fn publish_channel(&mut self, channel: &Arc<WaitChannel>) -> Result<(), NativeProcessError> {
        let zone = self.source.zone;
        let address = WaitChannel::address(channel);
        let guard = zone
            .lock(
                ZoneTables::<ParkedContextWords>::bucket_of_with_context(channel.mm, address),
                &BoundedSpin(LOCK_SPINS),
            )
            .ok_or(NativeProcessError::Busy)?;
        channel
            .generation
            .publish()
            .map_err(|_| NativeProcessError::Exhausted)?;
        let mut effects = WakeEffects::default();
        zone.wake_placed(
            &guard,
            channel.mm,
            address,
            u32::MAX,
            u32::MAX,
            Waker::El1 {
                slot: self.source.slot,
            },
            &mut [],
            &mut effects,
        )
        .map_err(|_| NativeProcessError::Busy)?;
        drop(guard);
        self.service.wake_effects(effects);
        Ok(())
    }
    fn exit_owned(&mut self, status: u8) -> Result<LifecycleOutcome, NativeProcessError> {
        self.exit_wait_status(LinuxWaitStatus::from_wait_encoding(i32::from(status) << 8))
    }
    fn exit_wait_status(
        &mut self,
        wait_status: LinuxWaitStatus,
    ) -> Result<LifecycleOutcome, NativeProcessError> {
        let root_exit = self.is_root_process();
        let (page, control) = {
            let graph = self.runtime.graph.lock();
            let resources = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
                .native()
                .resources();
            if resources.page.live() != 1 {
                return Err(NativeProcessError::Unsupported);
            }
            (resources.page, resources.control)
        };
        let transaction = self
            .runtime
            .graph
            .lock()
            .serials
            .allocate()
            .ok_or(NativeProcessError::Exhausted)?;
        let (resources, published) = {
            let mut graph = self.runtime.graph.lock();
            native_process_entry::publish_exit(
                &mut graph.owner,
                self.key,
                None,
                transaction,
                wait_status,
            )
            .map_err(|_| NativeProcessError::Busy)?
        };
        let record = self
            .source
            .zone
            .slot(self.source.slot)
            .current()
            .or_else(|| self.source.zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Quarantined)?;
        self.handoff =
            carrick_core::entry::retire_current(self.binding, self.source, record, LOCK_SPINS);
        if self.handoff.is_none() {
            return Err(NativeProcessError::Quarantined);
        }
        page.release_live(0)
            .map_err(|_| NativeProcessError::Quarantined)?;
        if let Some(entry) = control.entry() {
            page.retire_published(entry)
                .map_err(|_| NativeProcessError::Quarantined)?;
        }
        let permit = published.effects.cancel_members(|member| {
            if member.zone.live(member.record).is_some() {
                let _ = member.zone.claim_for_host(
                    member.record,
                    None,
                    Handback::Cancelled,
                    &BoundedSpin(LOCK_SPINS),
                );
            }
        });
        let (target, channel) = {
            let graph = self.runtime.graph.lock();
            let target = graph.owner.select_exit_parent(&permit);
            let channel = permit
                .parent()
                .and_then(|key| graph.owner.task(key).ok())
                .and_then(|row| row.native().resources().channel.clone());
            (target, channel)
        };
        if let Some(target) = target {
            let notification = target.prepare();
            if let Some(signal) = notification.signal {
                let signals = {
                    let graph = self.runtime.graph.lock();
                    graph
                        .owner
                        .task(notification.parent)
                        .map_err(|_| NativeProcessError::Stale)?
                        .native()
                        .resources()
                        .signals
                        .clone()
                };
                let signal = carrick_signal_core::policy::Signal::from_number(signal.raw())
                    .ok_or(NativeProcessError::Invalid)?;
                signals
                    .enqueue(notification.parent, signal, None)
                    .map_err(|_| NativeProcessError::Stale)?;
            }
        }
        if let Some(channel) = channel {
            self.publish_channel(&channel)?
        }
        if let Some(mm) = resources {
            self.service.retire_mm(mm)
        }
        drop(published.retiring);
        drop(published.autoreaped_receipt);
        if root_exit {
            self.root_exit = Some(wait_status);
        }
        Ok(LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            result: SyscallResult::new(0),
        })
    }
    fn fork_owned(&mut self) -> Result<u32, NativeProcessError> {
        let (
            snapshot,
            permit,
            child_key,
            thread_serial,
            child_mm,
            visible,
            claim,
            thread_claim,
            parent_mm,
            identity,
            group,
            session,
            signals,
        ) = {
            let mut graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            let parent_mm = row.native().resources().mm.clone();
            let identity = row.identity();
            let group = row.metadata().namespace_process_group;
            let session = row.metadata().namespace_session;
            let signals = row.native().resources().signals.clone();
            let snapshot = graph
                .owner
                .capture_parent(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            let serial = graph
                .serials
                .allocate()
                .ok_or(NativeProcessError::Exhausted)?;
            let thread_serial = graph
                .serials
                .allocate()
                .ok_or(NativeProcessError::Exhausted)?;
            let child_mm = MmGeneration::new(
                graph
                    .serials
                    .allocate()
                    .ok_or(NativeProcessError::Exhausted)?,
            );
            let transaction = graph
                .serials
                .allocate()
                .ok_or(NativeProcessError::Exhausted)?;
            let namespace = graph.namespace.clone();
            let visible_namespace = graph.visible_namespace;
            let (number, visible) = {
                let mut ns = namespace.lock();
                let number = ns
                    .reserve_next(ClaimKind::Task)
                    .map_err(|_| NativeProcessError::Exhausted)?;
                if ns.claim_related(number.get(), ClaimKind::Thread).is_err() {
                    ns.release(number, ClaimKind::Task);
                    return Err(NativeProcessError::Exhausted);
                }
                let Some(visible) = ns.reserve_visible(visible_namespace) else {
                    ns.release(number, ClaimKind::Thread);
                    ns.release(number, ClaimKind::Task);
                    return Err(NativeProcessError::Exhausted);
                };
                (number, visible)
            };
            let child_key = TaskKey {
                id: TaskId::from_abi_positive(number.get())
                    .map_err(|_| NativeProcessError::Invalid)?,
                serial: TaskSerial::from_raw_u64(serial.get())
                    .ok_or(NativeProcessError::Invalid)?,
            };
            let claim = NativeClaim {
                namespace: namespace.clone(),
                claims: vec![(number, ClaimKind::Task)],
            };
            let thread_claim = NativeClaim {
                namespace,
                claims: vec![(number, ClaimKind::Thread)],
            };
            let permit = graph
                .owner
                .reserve_birth(snapshot, snapshot, transaction)
                .map_err(|_| NativeProcessError::Busy)?;
            (
                snapshot,
                permit,
                child_key,
                thread_serial,
                child_mm,
                visible,
                claim,
                thread_claim,
                parent_mm,
                identity,
                group,
                session,
                signals,
            )
        };
        let signals = match signals.for_fork(child_key) {
            Some(signals) => signals,
            None => {
                self.runtime.graph.lock().owner.rollback_birth(&permit);
                return Err(NativeProcessError::Invalid);
            }
        };
        let (parent_identity, blocked, parent_page) = {
            let graph = self.runtime.graph.lock();
            let resources = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
                .native()
                .resources();
            (
                self.source.zone.record(resources.record.id).identity(),
                resources.control.blocked(),
                resources.page,
            )
        };
        let prepared = match self.service.prepare_mm(&parent_mm, self.words, child_mm) {
            Ok(p) => p,
            Err(error) => {
                self.runtime.graph.lock().owner.rollback_birth(&permit);
                return Err(error);
            }
        };
        let address = self.service.prepared_context(&prepared);
        if address.mm != child_mm {
            self.runtime.graph.lock().owner.rollback_birth(&permit);
            if let Err((_, p)) = self.service.abort_mm(prepared) {
                self.service.quarantine_prepared(p)
            };
            return Err(NativeProcessError::Stale);
        }
        let lifecycle = self.service.child_lifecycle(&prepared);
        let page = lifecycle.page;
        let metadata = (|| {
            if core::ptr::eq(page, parent_page)
                || page.live() != 1
                || lifecycle.controls.len() < page.entry_count() + 1
                || (0..page.entry_count()).any(|index| {
                    !matches!(
                        page.state(index),
                        Some((_, carrick_el1_abi::EntryState::Vacant))
                    )
                })
            {
                return Err(NativeProcessError::Invalid);
            }
            let lifecycle_entry = (0..page.entry_count())
                .find_map(|index| {
                    page.stock(
                        index,
                        EntryIdentity {
                            tid: child_key.id.raw() as u32,
                            visible_tid: visible.get(),
                            thread_serial: thread_serial.get(),
                            uid_credit: 0,
                        },
                    )
                    .ok()
                })
                .ok_or(NativeProcessError::Exhausted)?;
            let control = lifecycle
                .born_slot(lifecycle_entry)
                .ok_or(NativeProcessError::Invalid)?;
            page.bind_control_address(lifecycle_entry, control as *const _ as u64)
                .map_err(|_| NativeProcessError::Invalid)?;
            let claim = page
                .claim(lifecycle_entry)
                .map_err(|_| NativeProcessError::Busy)?;
            control.reset_for_birth(blocked, 0, lifecycle_entry);
            if !control.publish_visible_tid(visible.get()) {
                return Err(NativeProcessError::Invalid);
            }
            let born = page
                .record_born(
                    claim,
                    carrick_el1_abi::BornRecord {
                        caller_task: self.key.id.raw() as u64,
                        caller_serial: parent_identity.serial,
                        clone_flags: 0,
                        clear_child_tid: 0,
                        blocked,
                    },
                )
                .map_err(|_| NativeProcessError::Invalid)?;
            page.publish(born)
                .map_err(|_| NativeProcessError::Invalid)?;
            Ok(control)
        })();
        let control = match metadata {
            Ok(control) => control,
            Err(error) => {
                self.runtime.graph.lock().owner.rollback_birth(&permit);
                // The exact prepared MM retains potentially partially admitted
                // metadata. It must never be published or reused after refusal.
                self.service.quarantine_prepared(prepared);
                return Err(error);
            }
        };
        let thread = ThreadIdentity {
            tid: child_key.id.raw() as u64,
            serial: thread_serial.get(),
            mm: child_mm.raw().get(),
            file_table: parent_identity.file_table,
            generation: child_key.serial.raw(),
            affinity: parent_identity.affinity,
            lifecycle_page: page as *const _ as u64,
            control_slot: control as *const _ as u64,
        };
        let record = match self.source.zone.alloc_record(thread) {
            Ok(r) => r,
            Err(_) => {
                self.runtime.graph.lock().owner.rollback_birth(&permit);
                if let Err((_, p)) = self.service.abort_mm(prepared) {
                    self.service.quarantine_prepared(p)
                };
                return Err(NativeProcessError::Exhausted);
            }
        };
        let mut frame = self.words.frame;
        frame[10] = 0;
        let child_words = ParkedContextWords::from_parts(
            frame,
            address,
            self.words.fs_base,
            self.words.gs_base,
            self.words.xsave,
        );
        // SAFETY: this exact newly allocated record remains Free and unpublished.
        unsafe { *self.source.zone.record(record).ctx_mut() = child_words };
        let resources = NativeResources {
            key: child_key,
            zone: self.source.zone,
            record: self.source.zone.record_ref(record),
            control,
            page,
            mm: self.service.prepared_mm(&prepared),
            address,
            signals,
            _thread_claim: thread_claim,
            channel: None,
            usage: TaskRusage::default(),
        };
        let child = GuestTask::new(
            GuestTaskMetadata {
                key: child_key,
                container: (),
                namespace_pid: visible.get(),
                identity,
                namespace_process_group: group,
                namespace_session: session,
                ruid: (),
                euid: (),
                exit_signal: ChildExitSignal::SIGCHLD,
                diagnostic_name: String::from("native-child"),
            },
            Some(self.key),
            child_words,
            custody(resources),
            claim,
        );
        let prep = PreparedFork::from_reserved(
            snapshot,
            snapshot,
            child,
            prepared,
            BirthAttachment::Parent,
            permit,
        );
        let result = {
            let mut graph = self.runtime.graph.lock();
            prep.try_publish_with(&mut graph.owner, |prepared| {
                self.service.commit_mm(prepared)
            })
        };
        let published = match result {
            Ok(p) => p,
            Err(failure) => {
                let (error, prep) = match failure {
                    ForkTryError::Admission(_, prep) => (NativeProcessError::Busy, prep),
                    ForkTryError::Commit(error, prep) => (error, prep),
                };
                let returned = {
                    let mut graph = self.runtime.graph.lock();
                    prep.abort(&mut graph.owner)
                };
                match returned {
                    Ok((child, prepared)) => {
                        self.source.zone.free_record(record);
                        drop(child);
                        if let Err((_, p)) = self.service.abort_mm(prepared) {
                            self.service.quarantine_prepared(p)
                        }
                    }
                    Err(prepared) => {
                        self.service.quarantine_fork(*prepared);
                        return Err(NativeProcessError::Quarantined);
                    }
                };
                return Err(error);
            }
        };
        if self
            .runtime
            .graph
            .lock()
            .owner
            .release_birth(&published.reservation)
            .is_err()
        {
            self.service.quarantine_born(published.born);
            return Err(NativeProcessError::Quarantined);
        }
        if let Err((_, born)) = self.service.settle_mm(published.born) {
            self.service.quarantine_born(born);
            return Err(NativeProcessError::Quarantined);
        }
        self.source.zone.requeue_preempted(self.source.slot, record);
        Ok(visible.get())
    }
}
impl<'a, M: Clone, S: NativeProcessService<'a, Mm = M>> ProcessNative<ParkedContextWords>
    for NativeProcessEntry<'_, 'a, M, S>
{
    fn signal_action(
        &mut self,
        signal: carrick_signal_core::policy::Signal,
        replacement: Option<carrick_signal_core::policy::Action>,
    ) -> Option<Result<carrick_signal_core::policy::Action, SyscallResult>> {
        let signals = {
            let graph = self.runtime.graph.lock();
            let row = match graph.owner.task(self.key) {
                Ok(row) => row,
                Err(_) => return Some(Err(SyscallResult::new(-3))),
            };
            row.native().resources().signals.clone()
        };
        Some(match replacement {
            Some(action) => signals
                .install_action(self.key, signal, action)
                .map_err(|_| SyscallResult::new(-22)),
            None => Ok(signals.action(signal)),
        })
    }
    fn thread_signal(
        &mut self,
        request: carrick_personality_linux::signal_syscalls::ThreadSignalRequest,
    ) -> Option<LifecycleOutcome> {
        use carrick_signal_core::{SignalSet, policy::SigBlockMask};
        let (pid, tid, signals, mask) = {
            let graph = self.runtime.graph.lock();
            let row = match graph.owner.task(self.key) {
                Ok(row) => row,
                Err(_) => return Some(returned(-3)),
            };
            let resources = row.native().resources();
            (
                row.metadata().namespace_pid,
                resources.control.visible_tid(),
                resources.signals.clone(),
                resources.control.blocked(),
            )
        };
        if !tid.is_some_and(|tid| request.matches(pid, tid)) {
            return Some(returned(-3));
        }
        let Some(signal) = request.signal() else {
            return Some(returned(0));
        };
        let mask = SigBlockMask::blocking_all_of(SignalSet::from_bits(mask.0));
        if let Err(error) = signals.queue_self(self.key, signal, mask) {
            return Some(returned(match error {
                NativeSignalError::Stale => -3,
                NativeSignalError::Unsupported => -95,
            }));
        }
        self.resume_signals()
    }
    fn resume_signals(&mut self) -> Option<LifecycleOutcome> {
        use carrick_signal_core::{
            SignalSet,
            policy::{Delivery, SigBlockMask},
        };
        let (signals, mask) = {
            let graph = self.runtime.graph.lock();
            let row = match graph.owner.task(self.key) {
                Ok(row) => row,
                Err(_) => return Some(returned(-3)),
            };
            let resources = row.native().resources();
            (
                resources.signals.clone(),
                SigBlockMask::blocking_all_of(SignalSet::from_bits(resources.control.blocked().0)),
            )
        };
        // At most 64 signal keys; default-ignored standard signals coalesce.
        // Fatal delivery ends this turn, unsupported delivery retains its entry.
        for _ in 0..64 {
            let (signal, delivery) = match signals.take_self(self.key, mask) {
                Ok(Some(delivery)) => delivery,
                Ok(None) => return Some(returned(0)),
                Err(error) => {
                    return Some(returned(match error {
                        NativeSignalError::Stale => -3,
                        NativeSignalError::Unsupported => -95,
                    }));
                }
            };
            match delivery {
                Delivery::Ignore | Delivery::Continue => {}
                Delivery::Terminate { core_dump } => {
                    let status = LinuxWaitStatus::from_wait_encoding(
                        signal.number() | if core_dump { 128 } else { 0 },
                    );
                    return Some(match self.exit_wait_status(status) {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            // Failed retirement must not consume an admitted signal.
                            if signals.enqueue(self.key, signal, None).is_err() {
                                return Some(self.fail(NativeProcessError::Stale));
                            }
                            self.fail(error)
                        }
                    });
                }
                _ => return Some(returned(-95)),
            }
        }
        Some(returned(0))
    }
    fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    fn take_handoff_receipt(&mut self) -> Option<EntryHandoffReceipt<ParkedContextWords>> {
        self.handoff.take()
    }
    fn fork(&mut self) -> LifecycleOutcome {
        match self.fork_owned() {
            Ok(pid) => returned(i64::from(pid)),
            Err(error) => self.fail(error),
        }
    }
    fn wait4(
        &mut self,
        _pid: ProcessWaitPid,
        _status: UserVa,
        _options: LinuxWaitOptions,
        _rusage: UserVa,
    ) -> LifecycleOutcome {
        if _rusage.raw() != 0 {
            return self.fail(NativeProcessError::Unsupported);
        }
        let query = match self.query(_pid, _options) {
            Ok(query) => query,
            Err(error) => return self.fail(error),
        };
        match self.wait_query(query, _status, _options.contains(LinuxWaitOptions::WNOHANG)) {
            Ok(outcome) => outcome,
            Err(error) => self.fail(error),
        }
    }
    fn exit_group(&mut self, status: u8) -> LifecycleOutcome {
        match self.exit_owned(status) {
            Ok(outcome) => outcome,
            Err(error) => self.fail(error),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa};
    struct Physical<'a> {
        zone: &'a ZoneTables<ParkedContextWords>,
        page: &'a ThreadLifecyclePage,
        controls: &'a [ThreadControlSlot],
        copies: Vec<LinuxWaitStatus>,
        refuse_copy: bool,
    }
    impl<'a> NativeProcessService<'a> for Physical<'a> {
        type Mm = AddressContext<RootGpa>;
        type PreparedMm = AddressContext<RootGpa>;
        type Born = AddressContext<RootGpa>;
        fn prepare_mm(
            &mut self,
            _: &Self::Mm,
            _: ParkedContextWords,
            child: MmGeneration,
        ) -> Result<Self::PreparedMm, NativeProcessError> {
            let address = AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap(),
                mm: child,
                generation: ContextGeneration::new(NonZeroU64::MIN),
            };
            self.zone
                .spaces
                .publish_closed(child.raw().get(), address.root.address().raw(), 0)
                .ok_or(NativeProcessError::Exhausted)?;
            Ok(address)
        }
        fn prepared_mm(&self, p: &Self::PreparedMm) -> Self::Mm {
            *p
        }
        fn prepared_context(&self, p: &Self::PreparedMm) -> AddressContext<RootGpa> {
            *p
        }
        fn child_lifecycle(&self, _: &Self::PreparedMm) -> NativeLifecycleResources<'a> {
            NativeLifecycleResources {
                page: self.page,
                controls: self.controls,
            }
        }
        fn commit_mm(
            &mut self,
            p: Self::PreparedMm,
        ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
            Ok(p)
        }
        fn abort_mm(
            &mut self,
            p: Self::PreparedMm,
        ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
            self.zone
                .spaces
                .free(self.zone.spaces.find(p.mm.raw().get()).unwrap());
            Ok(())
        }
        fn settle_mm(&mut self, b: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
            self.zone
                .spaces
                .open(self.zone.spaces.find(b.mm.raw().get()).unwrap());
            Ok(())
        }
        fn copy_status(
            &mut self,
            _: &Self::Mm,
            _: UserVa,
            status: LinuxWaitStatus,
        ) -> Result<(), NativeProcessError> {
            if self.refuse_copy {
                return Err(NativeProcessError::Fault);
            };
            self.copies.push(status);
            Ok(())
        }
        fn quarantine_prepared(&mut self, _: Self::PreparedMm) {
            panic!("unexpected quarantine")
        }
        fn quarantine_fork(&mut self, _: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm>) {
            panic!("unexpected fork quarantine")
        }
        fn quarantine_born(&mut self, _: Self::Born) {
            panic!("unexpected quarantine")
        }
        fn retire_mm(&mut self, _: Self::Mm) {}
        fn wake_effects(&mut self, _: WakeEffects) {}
    }
    fn words(address: AddressContext<RootGpa>) -> ParkedContextWords {
        let mut frame = [0; 20];
        frame[15] = 0x400000;
        frame[16] = 0x23;
        frame[17] = 0x202;
        frame[18] = 0x800000;
        frame[19] = 0x1b;
        ParkedContextWords::from_parts(
            frame,
            address,
            0x9000,
            0,
            [0; carrick_sched_core::X86_XSAVE_BYTES],
        )
    }
    #[test]
    fn compact_native_wait_bucket_uses_the_shared_hash_for_its_context_abi() {
        for (mm, address) in [(1, 0), (104, 0xffff_ffff_a800_0000), (u64::MAX, u64::MAX)] {
            assert_eq!(
                ZoneTables::<ParkedContextWords>::bucket_of_with_context(mm, address),
                ZoneTables::bucket_of(mm, address)
            );
        }
    }
    #[test]
    fn actual_compact_root_can_exit_before_its_first_park() {
        exercise_root_exit(false, false);
    }
    #[test]
    fn actual_compact_root_owns_actions_and_self_signal_termination() {
        exercise_root_exit(true, false);
    }
    #[test]
    fn actual_compact_root_delivers_queued_self_signal_after_mask_restore() {
        exercise_root_exit(true, true);
    }
    fn exercise_root_exit(signaled: bool, blocked: bool) {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: the aligned allocation owns the complete zero-valid compact zone.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let page = Box::new(ThreadLifecyclePage::new());
        let control = Box::new(ThreadControlSlot::new());
        let child_page = Box::new(ThreadLifecyclePage::new());
        let child_controls = Box::new(core::array::from_fn::<_, 9, _>(|_| {
            ThreadControlSlot::new()
        }));
        let task = CurrentTask::new();
        task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
        task.mm.key.store(1, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_lifecycle(&*page as *const _ as u64, &*control as *const _ as u64);
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::MIN),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        };
        let slot = carrick_sched_core::SlotId::new(0);
        let space = zone.spaces.publish_closed(1, 0x1000, 0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 1, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, 1).unwrap();
        zone.current_or_new(
            slot,
            ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: 1,
                file_table: 5,
                generation: 11,
                affinity: 1,
                lifecycle_page: &*page as *const _ as u64,
                control_slot: &*control as *const _ as u64,
            },
        )
        .unwrap();
        let source = BornInZoneSource { zone: &zone, slot };
        assert_eq!(page.thread_born(), Some(2)); // retained legacy bootstrap census
        let runtime = NativeProcessRuntime::admit_fresh_root(
            source,
            &task,
            &page,
            &control,
            address,
            address,
            words(address),
        )
        .unwrap();
        assert_eq!(page.live(), 1);
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        assert!(zone.slot(slot).current().is_none());
        let home = zone.slot(slot).host_record().unwrap();
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let expected = if signaled { 6 | 128 } else { 9 << 8 };
        let outcome = if signaled {
            use carrick_signal_core::policy::{Action, Disposition, Signal};
            assert!(control.publish_visible_tid(41));
            let pipe = Signal::from_number(13).unwrap();
            let ignored = Action {
                disposition: Disposition::Ignore,
                ..Action::default()
            };
            assert_eq!(
                entry.signal_action(pipe, Some(ignored)).unwrap().unwrap(),
                Action::default()
            );
            assert_eq!(entry.signal_action(pipe, None).unwrap().unwrap(), ignored);
            for (group, tid, signal, expected) in [
                (None, 41_u32, 0_u32, 0),
                (Some(41_u32), 41, 0, 0),
                (Some(42), 41, 0, -3),
                (None, 42, 0, -3),
                (None, 41, 65, -22),
                (None, 41, 13, 0),
            ] {
                let request =
                    carrick_personality_linux::signal_syscalls::ThreadSignalRequest::decode(
                        group.map(u64::from),
                        u64::from(tid),
                        u64::from(signal),
                    );
                let result = match request {
                    Ok(request) => match entry.thread_signal(request).unwrap() {
                        LifecycleOutcome::Returned { result, .. } => result,
                        _ => panic!("signal probe transferred"),
                    },
                    Err(result) => result,
                };
                assert_eq!(result.raw(), expected);
            }
            let request = carrick_personality_linux::signal_syscalls::ThreadSignalRequest::decode(
                Some(41),
                41,
                6,
            )
            .unwrap();
            if blocked {
                use carrick_personality_linux::abi::thread::BlockedMask;
                let _ = control.store_blocked_then_read_pending(BlockedMask(32), control.pending());
                let LifecycleOutcome::Returned { result, work } =
                    entry.thread_signal(request).unwrap()
                else {
                    panic!("blocked signal retired");
                };
                assert_eq!(result.raw(), 0);
                assert!(!work);
                assert_eq!(page.live(), 1);
                assert!(entry.take_root_exit().is_none());
                let _ = control.store_blocked_then_read_pending(BlockedMask(0), control.pending());
                entry.resume_signals().unwrap()
            } else {
                entry.thread_signal(request).unwrap()
            }
        } else {
            entry.exit_group(9)
        };
        assert!(matches!(
            outcome,
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        assert_eq!(
            entry.take_root_exit(),
            Some(LinuxWaitStatus::from_wait_encoding(expected))
        );
        assert!(entry.take_handoff_receipt().is_some());
        assert_eq!(page.live(), 0);
        assert!(zone.slot(slot).host_record().is_none());
        assert!(zone.slot(slot).current().is_none());
        assert_eq!(zone.record(home).claim(), carrick_sched_core::Claim::Free);
    }

    #[test]
    fn actual_compact_root_forks_a_shared_owner_child_with_distinct_visible_identity() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: the aligned allocation owns the complete zero-valid compact zone.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let page = Box::new(ThreadLifecyclePage::new());
        let control = Box::new(ThreadControlSlot::new());
        let child_page = Box::new(ThreadLifecyclePage::new());
        let child_controls = Box::new(core::array::from_fn::<_, 9, _>(|_| {
            ThreadControlSlot::new()
        }));
        let task = CurrentTask::new();
        task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
        task.mm.key.store(1, Ordering::Release);
        task.mm.thread_generation.store(101, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_lifecycle(&*page as *const _ as u64, &*control as *const _ as u64);
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::MIN),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        };
        let slot = carrick_sched_core::SlotId::new(0);
        let space = zone.spaces.publish_closed(1, 0x1000, 0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 1, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, 1).unwrap();
        zone.current_or_new(
            slot,
            ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: 1,
                file_table: 5,
                generation: 11,
                affinity: 1,
                lifecycle_page: &*page as *const _ as u64,
                control_slot: &*control as *const _ as u64,
            },
        )
        .unwrap();
        let source = BornInZoneSource { zone: &zone, slot };
        assert_eq!(page.thread_born(), Some(2)); // retained legacy bootstrap census
        let runtime = NativeProcessRuntime::admit_fresh_root(
            source,
            &task,
            &page,
            &control,
            address,
            address,
            words(address),
        )
        .unwrap();
        assert_eq!(page.live(), 1);
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let parent = TaskKey {
            id: TaskId::from_abi_positive(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let child;
        {
            let mut entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            let LifecycleOutcome::Returned { result, .. } = entry.fork() else {
                panic!("fork return")
            };
            assert_eq!(result.raw(), 42);
            let parent = TaskKey {
                id: TaskId::from_abi_positive(41).unwrap(),
                serial: TaskSerial::from_raw_u64(11).unwrap(),
            };
            child = runtime.namespace_child_key(parent, 42).unwrap();
            assert_ne!(child, parent);
            assert_eq!(
                runtime.graph.lock().owner.task(child).unwrap().parent(),
                Some(parent)
            );
            assert!(matches!(
                entry.wait4(
                    ProcessWaitPid::from_syscall_argument(u64::MAX),
                    UserVa::new(0x8000),
                    LinuxWaitOptions::empty(),
                    UserVa::new(0)
                ),
                LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
            assert!(entry.take_handoff_receipt().is_some());
        }
        let (child_address, child_words, child_record) = {
            let graph = runtime.graph.lock();
            let row = graph.owner.task(child).unwrap();
            (
                row.native().resources().address,
                *row.context(),
                row.native().resources().record,
            )
        };
        assert_eq!(zone.switch_in_full(slot).unwrap().record, child_record.id);
        zone.install_space(slot, child_address.mm.raw().get())
            .unwrap();
        let child_identity = zone.record(child_record.id).identity();
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(child.id.raw()),
            child.serial.raw(),
            child_identity.file_table,
        );
        task.mm
            .key
            .store(child_address.mm.raw().get(), Ordering::Release);
        task.mm
            .thread_generation
            .store(child_identity.serial, Ordering::Release);
        task.publish_visible_pid(42);
        task.publish_lifecycle(child_identity.lifecycle_page, child_identity.control_slot);
        {
            let mut child_entry = runtime
                .enter(source, &task, child_words, &mut service)
                .unwrap();
            assert!(matches!(
                child_entry.exit_group(7),
                LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    ..
                }
            ));
            assert!(child_entry.take_handoff_receipt().is_some());
        }
        assert_eq!(child_page.live(), 0);
        assert_eq!(page.live(), 1);
        let parent_record = runtime
            .graph
            .lock()
            .owner
            .task(parent)
            .unwrap()
            .native()
            .resources()
            .record;
        assert_eq!(zone.switch_in_full(slot).unwrap().record, parent_record.id);
        zone.install_space(slot, address.mm.raw().get()).unwrap();
        let parent_identity = zone.record(parent_record.id).identity();
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(41),
            11,
            parent_identity.file_table,
        );
        task.mm.key.store(address.mm.raw().get(), Ordering::Release);
        task.mm
            .thread_generation
            .store(parent_identity.serial, Ordering::Release);
        task.publish_visible_pid(41);
        task.publish_lifecycle(parent_identity.lifecycle_page, parent_identity.control_slot);
        service.refuse_copy = true;
        {
            let mut parent_entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            let Some(LifecycleOutcome::Returned { result, .. }) =
                parent_entry.resume_pending_wait()
            else {
                panic!("resumed wait return")
            };
            assert_eq!(result.raw(), NativeProcessError::Fault.errno());
            assert!(runtime.namespace_child_key(parent, 42).is_some());
        }
        service.refuse_copy = false;
        let mut parent_entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = parent_entry.wait4(
            ProcessWaitPid::from_syscall_argument(42),
            UserVa::new(0x8000),
            LinuxWaitOptions::empty(),
            UserVa::new(0x9000),
        ) else {
            panic!("rusage refusal")
        };
        assert_eq!(result.raw(), NativeProcessError::Unsupported.errno());
        assert!(runtime.namespace_child_key(parent, 42).is_some());
        let LifecycleOutcome::Returned { result, .. } = parent_entry.wait4(
            ProcessWaitPid::from_syscall_argument(42),
            UserVa::new(0x8000),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        ) else {
            panic!("reap return")
        };
        assert_eq!(result.raw(), 42);
        assert!(runtime.namespace_child_key(parent, 42).is_none());
        assert!(parent_entry.take_root_exit().is_none());
        assert!(matches!(
            parent_entry.exit_group(9),
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        assert_eq!(
            parent_entry.take_root_exit(),
            Some(LinuxWaitStatus::from_wait_encoding(9 << 8))
        );
        assert!(parent_entry.take_root_exit().is_none());
        assert!(parent_entry.take_handoff_receipt().is_some());
        assert_eq!(page.live(), 0);
    }
}
