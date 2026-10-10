//! Native process custody over the shared guest owner and compact zone.
//! Root admission adopts the existing execution incarnation as a local process
//! incarnation; it does not import a host TaskSerial or launcher credentials.
extern crate alloc;
use super::{
    native_process_custody::{ProcessResources, ProcessWake, RetainedProcessCustody},
    native_process_entry::{self, CopiedWaitOutcome, ForkTryError, PreparedFork, WaitWork},
    native_process_signals::{NativeExitSignals, NativeProcessSignals},
    process_owner::*,
};
use crate::lock::SpinLock;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, EntryHandoffReceipt, EntryIdentity, EntryRef, ExecutionBinding,
    Lifecycle, ThreadControlSlot, ThreadLifecyclePage,
};
use carrick_guest_arch::{AddressContext, MmGeneration, ProcessContext, RootGpa, UserVa};
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
    BoundedSpin, Handback, RecordRef, ThreadIdentity, WakeEffects, Waker, ZoneTables,
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
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
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
pub trait NativeProcessService<'a, C: ProcessContext> {
    type Mm: Clone;
    type PreparedMm;
    type Born;
    fn prepare_mm(
        &mut self,
        parent: &Self::Mm,
        words: C,
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
    fn quarantine_fork(
        &mut self,
        prepared: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm, C>,
    );
    fn quarantine_born(&mut self, born: Self::Born);
    fn retire_mm(&mut self, mm: Self::Mm);
    fn wake_effects(&mut self, effects: WakeEffects);
    /// ARM keeps the parent's shared file table; a separately owned x86
    /// table takes a graph-issued identity for the new process.
    fn child_file_table(&self, parent_table: u64, _issued: u64) -> u64 {
        parent_table
    }
    fn fork_fd_table(
        &mut self,
        _parent_table: u64,
        _child_table: u64,
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }
    fn retire_fd_table(&mut self, _table: u64) {}
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
pub struct NativeMember<'a, C: ProcessContext> {
    key: TaskKey,
    zone: &'a ZoneTables<C>,
    record: RecordRef,
}
impl<C: ProcessContext> ExitMember for NativeMember<'_, C> {
    fn exit_task(&self) -> TaskKey {
        self.key
    }
}
pub struct NativeResources<'a, M, C: ProcessContext> {
    key: TaskKey,
    zone: &'a ZoneTables<C>,
    record: RecordRef,
    control: &'a ThreadControlSlot,
    page: &'a ThreadLifecyclePage,
    mm: M,
    address: AddressContext<RootGpa>,
    signals: NativeProcessSignals<()>,
    _thread_claim: NativeClaim,
    channel: Option<Arc<WaitChannel>>,
    usage: TaskRusage,
    file_table: u64,
}
pub type NativeForkPreparation<'a, M, P, C> = PreparedFork<
    VisibleNamespace,
    carrick_sched_core::process::TaskUid,
    RetainedProcessCustody<NativeResources<'a, M, C>>,
    P,
>;
impl<'a, M: Clone, C: ProcessContext> ProcessResources for NativeResources<'a, M, C> {
    type Context = C;
    type Claim = NativeClaim;
    type Event = ();
    type Transaction = NonZeroU64;
    type Member = NativeMember<'a, C>;
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
type Custody<'a, M, C> = RetainedProcessCustody<NativeResources<'a, M, C>>;
type NativeIdentityTask<'a, M, C> =
    GuestTask<VisibleNamespace, carrick_sched_core::process::TaskUid, Custody<'a, M, C>>;
type Owner<'a, M, C> =
    GuestProcessOwner<VisibleNamespace, carrick_sched_core::process::TaskUid, Custody<'a, M, C>>;
struct PendingWait {
    caller: TaskKey,
    query: WaitQuery,
    status: UserVa,
    precheck: WaitPrecheck,
    channel: Arc<WaitChannel>,
}
struct ExitWakeCustody {
    channel: Arc<WaitChannel>,
}
struct PendingExit {
    status: u8,
    channel: Arc<WaitChannel>,
    wake: Option<ExitWakeCustody>,
}
struct Graph<'a, M: Clone, C: ProcessContext> {
    owner: Owner<'a, M, C>,
    root_key: TaskKey,
    namespace: Arc<SpinLock<NamespaceState>>,
    visible_namespace: VisibleNamespace,
    serials: SerialAllocator,
    pending: BTreeMap<TaskKey, PendingWait>,
    pending_exit: BTreeMap<TaskKey, PendingExit>,
    _root_roles: NativeClaim,
    uts: carrick_personality_linux::sysinfo::LinuxUtsname,
}
pub struct NativeProcessRuntime<'a, M: Clone, C: ProcessContext> {
    graph: SpinLock<Graph<'a, M, C>>,
    zone: &'a ZoneTables<C>,
}
pub struct NativeRecordBinding<M, C: ProcessContext> {
    pub key: TaskKey,
    pub visible_pid: u32,
    pub mm: M,
    pub address: AddressContext<RootGpa>,
    pub words: C,
    pub record: RecordRef,
}
fn custody<'a, M: Clone, C: ProcessContext>(
    resources: NativeResources<'a, M, C>,
) -> Custody<'a, M, C> {
    let mut custody = RetainedProcessCustody::new(resources);
    let channel = Arc::new(WaitChannel {
        generation: custody.wake(),
        mm: custody.resources().record_identity_mm(),
    });
    custody.resources_mut().channel = Some(channel);
    custody
}
impl<M, C: ProcessContext> NativeResources<'_, M, C> {
    pub fn file_table(&self) -> u64 {
        self.file_table
    }
    fn record_identity_mm(&self) -> u64 {
        self.zone.record(self.record.id).identity().mm
    }
}
impl<'a, M: Clone, C: ProcessContext> NativeProcessRuntime<'a, M, C> {
    pub fn zone(&self) -> &'a ZoneTables<C> {
        self.zone
    }
    #[allow(clippy::too_many_arguments)]
    pub fn admit_fresh_root<B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
        source: BornInZoneSource<'a, C>,
        current: &'a CurrentTask,
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
        mm: M,
        address: AddressContext<RootGpa>,
        words: C,
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
            .is_none_or(|grant| B::root(grant.ttbr0).ok() != Some(address.root))
        {
            return Err(NativeProcessError::Stale);
        }
        // This constructor adopts one fresh leader. It cannot discard another
        // admitted member to repair an execution lane's bootstrap census.
        if page.live() != 1 {
            return Err(NativeProcessError::Invalid);
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
                        .max(binding.mm.raw())
                        .max(identity.file_table),
                )
                .ok_or(NativeProcessError::Invalid)?,
            )
            .ok_or(NativeProcessError::Exhausted)?;
        let file_table = if identity.file_table != 0 {
            identity.file_table
        } else {
            1
        };
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
            file_table,
        };
        let mut owner = Owner::new();
        owner
            .seed_initial(GuestTask::new(
                GuestTaskMetadata {
                    key,
                    container: visible_namespace,
                    namespace_pid: visible.get(),
                    identity: TaskIdentity::led_by(id),
                    namespace_process_group: visible.get(),
                    namespace_session: visible.get(),
                    receipt_uid: |uid| uid,
                    exit_signal: ChildExitSignal::SIGCHLD,
                    diagnostic_name: String::from("native-root"),
                },
                None,
                words,
                custody(resources),
                task_claim,
            ))
            .map_err(|_| NativeProcessError::Invalid)?;
        #[cfg(target_arch = "x86_64")]
        let uts = carrick_personality_linux::sysinfo::LinuxUtsname::carrick_x86_64();
        #[cfg(not(target_arch = "x86_64"))]
        let uts = carrick_personality_linux::sysinfo::LinuxUtsname::carrick_aarch64();
        if !control.publish_visible_tid(visible.get()) {
            return Err(NativeProcessError::Stale);
        }
        Ok(Self {
            graph: SpinLock::new(Graph {
                owner,
                root_key: key,
                namespace: ns,
                visible_namespace,
                serials,
                pending: BTreeMap::new(),
                pending_exit: BTreeMap::new(),
                _root_roles: root_roles,
                uts,
            }),
            zone: source.zone,
        })
    }
    pub fn enter<'r, S: NativeProcessService<'a, C, Mm = M>>(
        &'r self,
        source: BornInZoneSource<'a, C>,
        current: &'a CurrentTask,
        words: C,
        service: &'r mut S,
    ) -> Result<NativeProcessEntry<'r, 'a, M, C, S>, NativeProcessError> {
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
        let resources = row.native().resources();
        if current.metadata.lifecycle_page.load(Ordering::Acquire)
            != resources.page as *const _ as u64
            || current.metadata.control_slot.load(Ordering::Acquire)
                != resources.control as *const _ as u64
        {
            return Err(NativeProcessError::Stale);
        }
        let slot = Some(resources.control);
        let calling_tid = resources
            .control
            .visible_tid()
            .ok_or(NativeProcessError::Stale)?;
        row.credentials_for(calling_tid)
            .map_err(|_| NativeProcessError::Stale)?;
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
            run_failure: None,
            calling_tid,
            slot,
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
    pub fn record_binding(&self, record: RecordRef) -> Option<NativeRecordBinding<M, C>> {
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
            record: resources.record,
        })
    }
    pub fn task_binding(&self, key: TaskKey) -> Option<NativeRecordBinding<M, C>> {
        let graph = self.graph.lock();
        let row = graph.owner.task(key).ok()?;
        let resources = row.native().resources();
        Some(NativeRecordBinding {
            key,
            visible_pid: row.metadata().namespace_pid,
            mm: resources.mm.clone(),
            address: resources.address,
            words: *row.context(),
            record: resources.record,
        })
    }
    pub fn task_parent(&self, key: TaskKey) -> Option<Option<TaskKey>> {
        let graph = self.graph.lock();
        let row = graph.owner.task(key).ok()?;
        Some(row.parent())
    }
}
pub struct NativeProcessEntry<
    'r,
    'a,
    M: Clone,
    C: ProcessContext,
    S: NativeProcessService<'a, C, Mm = M>,
> {
    runtime: &'r NativeProcessRuntime<'a, M, C>,
    source: BornInZoneSource<'a, C>,
    binding: ExecutionBinding,
    key: TaskKey,
    words: C,
    service: &'r mut S,
    handoff: Option<EntryHandoffReceipt<C>>,
    root_exit: Option<LinuxWaitStatus>,
    run_failure: Option<carrick_el1_abi::NativeRunFailureReason>,
    calling_tid: u32,
    slot: Option<&'a ThreadControlSlot>,
}
fn returned(value: i64) -> LifecycleOutcome {
    LifecycleOutcome::Returned {
        result: SyscallResult::new(value),
        work: false,
    }
}
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    pub fn calling_tid(&self) -> u32 {
        self.calling_tid
    }
    pub fn set_calling_tid(&mut self, tid: u32) {
        self.calling_tid = tid;
    }
    pub fn set_slot_for_test(&mut self, slot: &'a ThreadControlSlot) {
        self.slot = Some(slot);
    }
    pub fn take_run_failure(&mut self) -> Option<carrick_el1_abi::NativeRunFailureReason> {
        self.run_failure.take()
    }
    fn run_failed(&mut self, reason: carrick_el1_abi::NativeRunFailureReason) -> LifecycleOutcome {
        self.run_failure = Some(reason);
        if let Some(record) = self
            .source
            .zone
            .slot(self.source.slot)
            .current()
            .or_else(|| self.source.zone.slot(self.source.slot).host_record())
        {
            self.handoff =
                carrick_core::entry::retire_current(self.binding, self.source, record, LOCK_SPINS);
        }
        // No graph exit or MM retirement is claimed. Even if lane retirement
        // refuses, the authenticated carrier report stops this incomplete run.
        LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            result: SyscallResult::new(0),
        }
    }
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
            p => WaitTarget::ProcessGroup(
                graph
                    .owner
                    .namespace_child_group(self.key, p.unsigned_abs())
                    .map_err(|_| NativeProcessError::Stale)?
                    .ok_or(NativeProcessError::NoChild)?,
            ),
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
        let mut rescan = None;
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
                let selected = match rescan.take() {
                    Some(selected) => selected,
                    None => native_process_entry::scan_wait(&graph.owner, self.key, query)
                        .map_err(|_| NativeProcessError::Busy)?,
                };
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
                    let consumed = match consumed {
                        CopiedWaitOutcome::Consumed(consumed) => consumed,
                        CopiedWaitOutcome::Rescan(selection) => {
                            rescan = Some(selection);
                            continue;
                        }
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
                            ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
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
                ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
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
    /// Resume owned lifecycle custody before the execution lane returns to EL0.
    /// Exit keeps its original status and cannot become a guest syscall return.
    pub fn resume_pending_lifecycle(
        &mut self,
    ) -> Result<Option<LifecycleOutcome>, NativeProcessError> {
        let status = self
            .runtime
            .graph
            .lock()
            .pending_exit
            .get(&self.key)
            .map(|p| p.status);
        if let Some(status) = status {
            return Ok(Some(self.exit_group(status)));
        }
        Ok(self.resume_pending_wait())
    }

    fn park_pending_exit(
        &mut self,
        page: &ThreadLifecyclePage,
        channel: &Arc<WaitChannel>,
    ) -> Result<Option<LifecycleOutcome>, NativeProcessError> {
        let zone = self.source.zone;
        let record = zone
            .slot(self.source.slot)
            .current()
            .or_else(|| zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Quarantined)?;
        let start = carrick_core::entry::prepare_handoff(self.binding, self.source, record)
            .ok_or(NativeProcessError::Quarantined)?;
        let address = WaitChannel::address(channel);
        let guard = zone
            .lock(
                ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
                &BoundedSpin(LOCK_SPINS),
            )
            .ok_or(NativeProcessError::Quarantined)?;
        // Settlement publishes under this same bucket. A claim which settled
        // before enrollment needs no wake; a later settlement owns our wake.
        if page.claimed_count() == 0 {
            return Ok(None);
        }
        let sequence = zone.next_seq(record);
        zone.enqueue(&guard, record, sequence, channel.mm, address, u32::MAX, 0)
            .map_err(|_| NativeProcessError::Quarantined)?;
        // SAFETY: the current record remains owned until its guarded park CAS.
        unsafe { *zone.record(record).ctx_mut() = self.words };
        let receipt = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_el1_abi::EntryRecordGeneration(sequence),
        )
        .ok_or(NativeProcessError::Quarantined)?;
        drop(guard);
        zone.clear_current(self.source.slot);
        self.handoff = Some(receipt);
        Ok(Some(LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            result: SyscallResult::new(0),
        }))
    }

    #[inline(never)]
    fn exit_owned(&mut self, status: u8) -> Result<LifecycleOutcome, NativeProcessError> {
        let (page, channel) = {
            let mut graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task_mut(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            row.select_exit_thread(self.calling_tid)
                .map_err(|_| NativeProcessError::Stale)?;
            let page = row.native().resources().page;
            if !graph.pending_exit.contains_key(&self.key) {
                // Already admitted sibling retirement still needs its own
                // exact-record cancellation binding. Pre-live claims are
                // refused by thread_spawned after this terminal close.
                if page.live() != 1 && page.claimed_count() == 0 {
                    drop(graph);
                    return Ok(self
                        .run_failed(carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody));
                }
                page.close();
                let channel = Arc::new(WaitChannel {
                    generation: ProcessWake::new(),
                    mm: self.binding.mm.raw(),
                });
                let wake = Some(ExitWakeCustody {
                    channel: channel.clone(),
                });
                graph.pending_exit.insert(
                    self.key,
                    PendingExit {
                        status,
                        channel,
                        wake,
                    },
                );
            }
            (
                page,
                graph
                    .pending_exit
                    .get(&self.key)
                    .ok_or(NativeProcessError::Quarantined)?
                    .channel
                    .clone(),
            )
        };
        if let Some(outcome) = self.park_pending_exit(page, &channel)? {
            return Ok(outcome);
        }
        if page.live() != 1 {
            return Ok(
                self.run_failed(carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody)
            );
        }
        let root_exit = self.is_root_process();
        let wait_status = LinuxWaitStatus::from_wait_encoding(i32::from(status) << 8);

        let transaction = self
            .runtime
            .graph
            .lock()
            .serials
            .allocate()
            .ok_or(NativeProcessError::Exhausted)?;
        let (page, control, file_table, resources, published) = {
            let mut graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task_mut(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            row.select_exit_thread(self.calling_tid)
                .map_err(|_| NativeProcessError::Stale)?;
            let page = row.native().resources().page;
            let control = row.native().resources().control;
            let file_table = row.native().resources().file_table;
            let (resources, published) = match native_process_entry::publish_exit(
                &mut graph.owner,
                self.key,
                None,
                transaction,
                wait_status,
            ) {
                Ok(published) => published,
                Err(_) => return Err(NativeProcessError::Quarantined),
            };
            graph.pending_exit.remove(&self.key);
            (page, control, file_table, resources, published)
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
        let (target, channels) = {
            let graph = self.runtime.graph.lock();
            let target = graph.owner.select_exit_parent(&permit);
            let mut channels = Vec::new();
            for key in [permit.parent(), published.adopter].into_iter().flatten() {
                if let Some(channel) = graph
                    .owner
                    .task(key)
                    .ok()
                    .and_then(|row| row.native().resources().channel.clone())
                    && !channels.iter().any(|other| Arc::ptr_eq(other, &channel))
                {
                    channels.push(channel);
                }
            }
            (target, channels)
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
        for channel in channels {
            self.publish_channel(&channel)?;
        }
        if let Some(mm) = resources {
            self.service.retire_mm(mm)
        }
        self.service.retire_fd_table(file_table);
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
    #[inline(never)]
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
            parent_creds,
            parent_rlimits,
            parent_umask,
            parent_personality,
            parent_dumpable,
            parent_no_new_privs,
            parent_comm,
            parent_container,
        ) = {
            let mut graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            if row.native().resources().page.gate() != carrick_el1_abi::GateState::Open {
                return Err(NativeProcessError::Busy);
            }
            let parent_mm = row.native().resources().mm.clone();
            let identity = row.identity();
            let group = row.metadata().namespace_process_group;
            let session = row.metadata().namespace_session;
            let signals = row.native().resources().signals.clone();
            let caller_tid = self.calling_tid;
            let parent_container = row.metadata().container;
            let parent_creds = row
                .credentials_for(caller_tid)
                .map_err(|_| NativeProcessError::Stale)?
                .clone();
            let parent_rlimits = row.rlimits;
            let parent_umask = row.umask;
            let parent_personality = row.personality;
            let parent_dumpable = row.dumpable;
            let parent_no_new_privs = row.no_new_privs;
            let parent_comm = *row
                .comm_for(caller_tid)
                .map_err(|_| NativeProcessError::Stale)?;
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
                parent_creds,
                parent_rlimits,
                parent_umask,
                parent_personality,
                parent_dumpable,
                parent_no_new_privs,
                parent_comm,
                parent_container,
            )
        };
        let signals = match signals.for_fork(child_key) {
            Some(signals) => signals,
            None => {
                self.runtime.graph.lock().owner.rollback_birth(&permit);
                return Err(NativeProcessError::Invalid);
            }
        };
        let (parent_identity, blocked, parent_page, parent_file_table) = {
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
                resources.file_table,
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
                page.unclaim(claim)
                    .map_err(|_| NativeProcessError::Quarantined)?;
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
                .map_err(|refusal| {
                    let (_, claim) = refusal.into_parts();
                    match page.unclaim(claim) {
                        Ok(_) => NativeProcessError::Invalid,
                        Err(_) => NativeProcessError::Quarantined,
                    }
                })?;
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
        let child_file_table = self
            .service
            .child_file_table(parent_file_table, child_key.serial.raw());
        let thread = ThreadIdentity {
            tid: child_key.id.raw() as u64,
            serial: thread_serial.get(),
            mm: child_mm.raw().get(),
            file_table: child_file_table,
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
        if let Err(error) = self
            .service
            .fork_fd_table(parent_file_table, child_file_table)
        {
            self.source.zone.free_record(record);
            self.runtime.graph.lock().owner.rollback_birth(&permit);
            if let Err((_, p)) = self.service.abort_mm(prepared) {
                self.service.quarantine_prepared(p)
            };
            return Err(error);
        }
        let child_words = self.words.fork_child(address);
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
            file_table: child_file_table,
        };
        let mut child = GuestTask::new(
            GuestTaskMetadata {
                key: child_key,
                container: parent_container,
                namespace_pid: visible.get(),
                identity,
                namespace_process_group: group,
                namespace_session: session,
                receipt_uid: |uid| uid,
                exit_signal: ChildExitSignal::SIGCHLD,
                diagnostic_name: String::from("native-child"),
            },
            Some(self.key),
            child_words,
            custody(resources),
            claim,
        );
        child.init_leader(visible.get(), parent_creds, parent_comm);
        child.rlimits = parent_rlimits;
        child.umask = parent_umask;
        child.personality = parent_personality;
        child.dumpable = parent_dumpable;
        child.no_new_privs = parent_no_new_privs;
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
                        self.service.retire_fd_table(child_file_table);
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
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>> ProcessNative<C>
    for NativeProcessEntry<'_, 'a, M, C, S>
{
    fn take_run_failure(&mut self) -> Option<carrick_el1_abi::NativeRunFailureReason> {
        self.run_failure.take()
    }
    fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    fn pid_exists(&self, pid: u32) -> Option<bool> {
        self.runtime
            .graph
            .lock()
            .owner
            .namespace_key(self.key, pid)
            .ok()
            .map(|key| key.is_some())
    }
    fn take_handoff_receipt(&mut self) -> Option<EntryHandoffReceipt<C>> {
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
            Err(_) => self.run_failed(carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody),
        }
    }
    fn as_identity_venue(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::identity::ProcessIdentityVenue> {
        Some(self)
    }
    fn as_sysinfo_venue(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::sysinfo::ProcessSysinfoVenue> {
        Some(self)
    }
    fn thread_spawned(
        &mut self,
        caller_tid: u32,
        child_tid: u32,
        publish: &mut dyn FnMut() -> Result<(), i64>,
    ) -> Result<(), i64> {
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if task.native().resources().page.gate() == carrick_el1_abi::GateState::Closed {
            return Err(-11);
        }
        if task.has_thread(child_tid) {
            return Err(carrick_personality_linux::identity::EINVAL);
        }
        task.spawn_thread(caller_tid, child_tid)?;
        if let Err(error) = publish() {
            task.remove_thread(child_tid);
            return Err(error);
        }
        Ok(())
    }
    fn thread_exited(&mut self, tid: u32) {
        self.thread_exited(tid);
    }
    fn lifecycle_admission_settled(&mut self) -> Result<(), i64> {
        let wake = {
            let mut graph = self.runtime.graph.lock();
            if graph.pending_exit.contains_key(&self.key) {
                let settled = graph
                    .owner
                    .task(self.key)
                    .map_err(|_| NativeProcessError::Quarantined)
                    .map(|row| row.native().resources().page.claimed_count() == 0);
                settled.map(|settled| {
                    if settled {
                        graph
                            .pending_exit
                            .get_mut(&self.key)
                            .and_then(|pending| pending.wake.take())
                    } else {
                        None
                    }
                })
            } else {
                Ok(None)
            }
        };
        // Graph ownership is released before acquiring any scheduler bucket.
        let published = wake.and_then(|wake| {
            if let Some(wake) = wake {
                self.publish_channel(&wake.channel)?;
            }
            Ok(())
        });
        if let Err(error) = published {
            // The sole pending-exit wake cannot be retried or discarded. The
            // active clone lane reports typed run failure before guest return.
            self.run_failure = Some(carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody);
            return Err(error.errno());
        }
        Ok(())
    }
    fn set_calling_tid(&mut self, tid: u32) {
        self.calling_tid = tid;
    }

    #[inline(never)]
    fn has_thread(&self, tid: u32) -> bool {
        let graph = self.runtime.graph.lock();
        if let Ok(task) = graph.owner.task(self.key) {
            task.has_thread(tid)
        } else {
            false
        }
    }
    fn read_robust_list(
        &self,
        tid: u32,
        read_slot: &mut carrick_personality_linux::lifecycle::RobustSlotReader<'_>,
    ) -> Result<(u64, u32), i64> {
        let graph = self.runtime.graph.lock();
        let target = self.robust_target(&graph.owner, tid)?;
        let resources = target.native().resources();
        if tid == target.metadata().namespace_pid {
            return Ok(resources.control.robust_list());
        }
        let entry = resources
            .page
            .entry_ref_for_visible_tid(tid)
            .ok_or(carrick_personality_linux::identity::ESRCH)?;
        read_slot(resources.page, entry).ok_or(carrick_personality_linux::identity::ESRCH)
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    #[inline(never)]
    pub fn thread_exited(&mut self, tid: u32) {
        let mut graph = self.runtime.graph.lock();
        if let Ok(task) = graph.owner.task_mut(self.key) {
            task.remove_thread(tid);
        }
    }

    fn robust_target<'g>(
        &self,
        owner: &'g Owner<'a, M, C>,
        tid: u32,
    ) -> Result<&'g NativeIdentityTask<'a, M, C>, i64> {
        use carrick_personality_linux::identity::{EPERM, ESRCH};
        use carrick_sched_core::process::LinuxCapabilitySet;
        let caller = owner.task(self.key).map_err(|_| ESRCH)?;
        let credentials = caller.credentials_for(self.calling_tid)?;
        let target = owner
            .find_task_by_thread(caller.metadata().container, tid)
            .filter(|row| row.native().resources().control.visible_tid().is_some())
            .ok_or(ESRCH)?;
        if target.key() == self.key {
            return Ok(target);
        }
        if credentials
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_SYS_PTRACE)
        {
            return Ok(target);
        }
        let peer = target.credentials_for(tid)?;
        let uid_matches = peer.ruid == credentials.fsuid
            && peer.euid == credentials.fsuid
            && peer.suid == credentials.fsuid;
        let gid_matches = peer.rgid == credentials.fsgid
            && peer.egid == credentials.fsgid
            && peer.sgid == credentials.fsgid;
        if uid_matches
            && gid_matches
            && target.dumpable == 1
            && credentials.cap_permitted.contains(peer.cap_permitted)
        {
            Ok(target)
        } else {
            Err(EPERM)
        }
    }

    #[inline(never)]
    fn update_calling_creds(
        &mut self,
        f: &mut dyn FnMut(&mut carrick_sched_core::process::TaskCredentials) -> Result<(), i64>,
    ) -> Result<(), i64> {
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        f(task.credentials_for_mut(self.calling_tid)?)?;
        Ok(())
    }
}

impl<'r, 'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    carrick_personality_linux::identity::ProcessIdentityVenue
    for NativeProcessEntry<'r, 'a, M, C, S>
{
    fn get_uids(
        &self,
    ) -> Result<(u32, u32, u32, u32), carrick_personality_linux::identity::IdentityReadError> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        let creds = task
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        Ok((
            creds.ruid.raw(),
            creds.euid.raw(),
            creds.suid.raw(),
            creds.fsuid.raw(),
        ))
    }
    fn get_gids(
        &self,
    ) -> Result<(u32, u32, u32, u32), carrick_personality_linux::identity::IdentityReadError> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        let creds = task
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        Ok((
            creds.rgid.raw(),
            creds.egid.raw(),
            creds.sgid.raw(),
            creds.fsgid.raw(),
        ))
    }

    fn set_resuid(&mut self, r: Option<u32>, e: Option<u32>, s: Option<u32>) -> Result<(), i64> {
        self.update_calling_creds(&mut |creds| creds.set_resuid(r, e, s))
    }

    fn set_resgid(&mut self, r: Option<u32>, e: Option<u32>, s: Option<u32>) -> Result<(), i64> {
        self.update_calling_creds(&mut |creds| creds.set_resgid(r, e, s))
    }

    fn set_reuid(&mut self, r: Option<u32>, e: Option<u32>) -> Result<(), i64> {
        self.update_calling_creds(&mut |creds| creds.set_reuid(r, e))
    }

    fn set_regid(&mut self, r: Option<u32>, e: Option<u32>) -> Result<(), i64> {
        self.update_calling_creds(&mut |creds| creds.set_regid(r, e))
    }

    fn set_uid(&mut self, uid: u32) -> Result<(), i64> {
        self.update_calling_creds(&mut |creds| creds.set_uid(uid))
    }

    fn set_gid(&mut self, gid: u32) -> Result<(), i64> {
        self.update_calling_creds(&mut |creds| creds.set_gid(gid))
    }

    fn set_fsuid(
        &mut self,
        fsuid: u32,
    ) -> Result<u32, carrick_personality_linux::identity::IdentityReadError> {
        let mut prev = None;
        self.update_calling_creds(&mut |creds| {
            prev = Some(creds.set_fsuid(fsuid));
            Ok(())
        })
        .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        prev.ok_or(carrick_personality_linux::identity::IdentityReadError::MissingThread)
    }

    fn set_fsgid(
        &mut self,
        fsgid: u32,
    ) -> Result<u32, carrick_personality_linux::identity::IdentityReadError> {
        let mut prev = None;
        self.update_calling_creds(&mut |creds| {
            prev = Some(creds.set_fsgid(fsgid));
            Ok(())
        })
        .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        prev.ok_or(carrick_personality_linux::identity::IdentityReadError::MissingThread)
    }

    fn can_set_groups(&self) -> Result<(), i64> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        let creds = task
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if !creds.is_gid_privileged() {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        Ok(())
    }

    fn get_groups_count(
        &self,
    ) -> Result<usize, carrick_personality_linux::identity::IdentityReadError> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        Ok(task
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?
            .groups
            .len())
    }
    fn get_groups(
        &self,
        out: &mut alloc::vec::Vec<u32>,
    ) -> Result<(), carrick_personality_linux::identity::IdentityReadError> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        let creds = task
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::identity::IdentityReadError::MissingThread)?;
        out.clear();
        out.extend(creds.groups.iter().map(|g| g.raw()));
        Ok(())
    }

    fn set_groups(&mut self, groups: &[u32]) -> Result<(), i64> {
        if groups.len() > carrick_personality_linux::identity::LINUX_NGROUPS_MAX {
            return Err(carrick_personality_linux::identity::EINVAL);
        }
        let mut parsed = Some(
            groups
                .iter()
                .copied()
                .map(carrick_sched_core::process::TaskGid::new)
                .collect::<alloc::vec::Vec<_>>(),
        );
        self.update_calling_creds(&mut |creds| {
            if !creds.is_gid_privileged() {
                return Err(carrick_personality_linux::identity::EPERM);
            }
            if let Some(p) = parsed.take() {
                creds.groups = p;
            }
            Ok(())
        })
    }

    fn capget(
        &self,
        pid: i32,
    ) -> Result<carrick_personality_linux::identity::TaskCapabilities, i64> {
        let graph = self.runtime.graph.lock();
        let caller = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if pid == 0 {
            let creds = caller.credentials_for(self.calling_tid)?;
            return Ok(carrick_personality_linux::identity::TaskCapabilities {
                effective: creds.cap_effective,
                permitted: creds.cap_permitted,
                inheritable: creds.cap_inheritable,
            });
        }
        let target_tid = pid as u32;
        if target_tid == caller.metadata().namespace_pid || caller.has_thread(target_tid) {
            let creds = caller.credentials_for(target_tid)?;
            return Ok(carrick_personality_linux::identity::TaskCapabilities {
                effective: creds.cap_effective,
                permitted: creds.cap_permitted,
                inheritable: creds.cap_inheritable,
            });
        }
        let target = graph
            .owner
            .find_task_by_pid(target_tid)
            .filter(|row| row.native().resources().control.visible_tid().is_some())
            .ok_or(carrick_personality_linux::identity::ESRCH)?;
        let creds = target.credentials_for(target_tid)?;
        Ok(carrick_personality_linux::identity::TaskCapabilities {
            effective: creds.cap_effective,
            permitted: creds.cap_permitted,
            inheritable: creds.cap_inheritable,
        })
    }

    fn capset(
        &mut self,
        pid: i32,
        caps: carrick_personality_linux::identity::TaskCapabilities,
    ) -> Result<(), i64> {
        let mut graph = self.runtime.graph.lock();
        let caller_tid = self.calling_tid;
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if pid < 0 || (pid != 0 && pid as u32 != caller_tid) {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        let caller_creds = task.credentials_for(caller_tid)?;
        if !caller_creds.cap_permitted.contains(caps.permitted) {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        let has_setpcap = caller_creds
            .cap_effective
            .contains(carrick_personality_linux::identity::LinuxCapabilitySet::CAP_SETPCAP);
        if !has_setpcap {
            let allowed_inh = caller_creds
                .cap_inheritable
                .union(caller_creds.cap_permitted);
            if !allowed_inh.contains(caps.inheritable) {
                return Err(carrick_personality_linux::identity::EPERM);
            }
        }
        let target_creds = task.credentials_for_mut(caller_tid)?;
        target_creds.cap_effective = caps.effective;
        target_creds.cap_permitted = caps.permitted;
        target_creds.cap_inheritable = caps.inheritable;
        Ok(())
    }

    fn get_ppid(&self) -> u32 {
        let graph = self.runtime.graph.lock();
        let Ok(task) = graph.owner.task(self.key) else {
            return 0;
        };
        if task.metadata().namespace_pid == 1 {
            return 0;
        }
        let Some(parent_key) = task.parent() else {
            return 0;
        };
        let Ok(parent) = graph.owner.task(parent_key) else {
            return 0;
        };
        if parent.metadata().container != task.metadata().container {
            return 0;
        }
        parent.metadata().namespace_pid
    }

    fn get_pgid(&self, pid: i32) -> Result<u32, i64> {
        let graph = self.runtime.graph.lock();
        let caller = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if pid == 0 || pid as u32 == caller.metadata().namespace_pid {
            Ok(caller.metadata().namespace_process_group)
        } else if let Some(target) = graph
            .owner
            .find_task_by_pid(pid as u32)
            .filter(|row| row.native().resources().control.visible_tid().is_some())
        {
            Ok(target.metadata().namespace_process_group)
        } else {
            Err(carrick_personality_linux::identity::ESRCH)
        }
    }

    fn set_pgid(&mut self, pid: i32, pgid: i32) -> Result<(), i64> {
        if pgid < 0 {
            return Err(carrick_personality_linux::identity::EINVAL);
        }
        let mut graph = self.runtime.graph.lock();
        let caller = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        let caller_pid = caller.metadata().namespace_pid;
        let caller_session = caller.metadata().namespace_session;
        let caller_key = self.key;
        let target_pid = if pid == 0 { caller_pid } else { pid as u32 };
        let new_pgid = if pgid == 0 { target_pid } else { pgid as u32 };

        if target_pid != caller_pid {
            let target = graph
                .owner
                .find_task_by_pid(target_pid)
                .filter(|row| row.native().resources().control.visible_tid().is_some())
                .ok_or(carrick_personality_linux::identity::ESRCH)?;
            if target.parent() != Some(caller_key) {
                return Err(carrick_personality_linux::identity::ESRCH);
            }
            if target.has_execed {
                return Err(carrick_personality_linux::identity::EACCES);
            }
        }

        let (target_session, is_session_leader) = {
            let target = if target_pid == caller_pid {
                caller
            } else {
                graph
                    .owner
                    .find_task_by_pid(target_pid)
                    .filter(|row| row.native().resources().control.visible_tid().is_some())
                    .ok_or(carrick_personality_linux::identity::ESRCH)?
            };
            (
                target.metadata().namespace_session,
                target.metadata().namespace_session == target.metadata().namespace_pid,
            )
        };

        if target_session != caller_session {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        if is_session_leader {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        if new_pgid != target_pid
            && !graph
                .owner
                .group_exists_in_session(caller_session, new_pgid)
        {
            return Err(carrick_personality_linux::identity::EPERM);
        }

        let target = if target_pid == caller_pid {
            graph
                .owner
                .task_mut(self.key)
                .map_err(|_| carrick_personality_linux::identity::ESRCH)?
        } else {
            graph
                .owner
                .find_task_by_pid_mut(target_pid)
                .filter(|row| row.native().resources().control.visible_tid().is_some())
                .ok_or(carrick_personality_linux::identity::ESRCH)?
        };
        target.metadata_mut().namespace_process_group = new_pgid;
        if let Ok(gid) =
            carrick_sched_core::process::ProcessGroupId::from_abi_positive(new_pgid as i32)
        {
            target.metadata_mut().identity.process_group = gid;
        }
        Ok(())
    }

    fn get_sid(&self, pid: i32) -> Result<u32, i64> {
        let graph = self.runtime.graph.lock();
        let caller = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if pid == 0 || pid as u32 == caller.metadata().namespace_pid {
            Ok(caller.metadata().namespace_session)
        } else if let Some(target) = graph
            .owner
            .find_task_by_pid(pid as u32)
            .filter(|row| row.native().resources().control.visible_tid().is_some())
        {
            Ok(target.metadata().namespace_session)
        } else {
            Err(carrick_personality_linux::identity::ESRCH)
        }
    }

    fn set_sid(&mut self) -> Result<u32, i64> {
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        let pid = task.metadata().namespace_pid;
        if pid == task.metadata().namespace_process_group {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        task.metadata_mut().namespace_session = pid;
        task.metadata_mut().namespace_process_group = pid;
        if let Ok(sid) = carrick_sched_core::process::SessionId::from_abi_positive(pid as i32) {
            task.metadata_mut().identity.session = sid;
        }
        if let Ok(gid) = carrick_sched_core::process::ProcessGroupId::from_abi_positive(pid as i32)
        {
            task.metadata_mut().identity.process_group = gid;
        }
        Ok(pid)
    }

    fn personality(&mut self, persona: u64) -> u64 {
        let mut graph = self.runtime.graph.lock();
        let Ok(task) = graph.owner.task_mut(self.key) else {
            return 0;
        };
        if persona == 0xffff_ffff {
            task.personality
        } else {
            let old = task.personality;
            task.personality = persona;
            old
        }
    }

    fn prctl_get_name(
        &self,
        buf: &mut [u8; 16],
    ) -> Result<(), carrick_personality_linux::identity::IdentityReadError> {
        use carrick_personality_linux::identity::IdentityReadError;
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| IdentityReadError::MissingThread)?;
        let comm = task
            .comm_for(self.calling_tid)
            .map_err(|_| IdentityReadError::MissingThread)?;
        *buf = *comm;
        Ok(())
    }

    fn prctl_set_name(&mut self, name: &[u8; 16]) {
        let mut bounded = *name;
        bounded[15] = 0;
        let mut graph = self.runtime.graph.lock();
        if let Ok(task) = graph.owner.task_mut(self.key) {
            let caller_tid = self.calling_tid;
            let is_leader = caller_tid == task.metadata().namespace_pid;
            if let Ok(comm) = task.comm_for_mut(caller_tid) {
                *comm = bounded;
            }
            if is_leader {
                let len = bounded.iter().position(|&b| b == 0).unwrap_or(15);
                if let Ok(s) = core::str::from_utf8(&bounded[..len]) {
                    task.metadata_mut().diagnostic_name = alloc::string::String::from(s);
                }
            }
        }
    }

    fn prctl_get_pdeathsig(&self) -> u8 {
        let graph = self.runtime.graph.lock();
        graph.owner.task(self.key).map(|t| t.pdeathsig).unwrap_or(0)
    }

    fn prctl_set_pdeathsig(&mut self, sig: u8) -> Result<(), i64> {
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        task.pdeathsig = sig;
        Ok(())
    }

    fn prctl_get_dumpable(&self) -> u32 {
        let graph = self.runtime.graph.lock();
        graph.owner.task(self.key).map(|t| t.dumpable).unwrap_or(1)
    }

    fn prctl_set_dumpable(&mut self, dumpable: u32) -> Result<(), i64> {
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if dumpable > 2 {
            return Err(carrick_personality_linux::identity::EINVAL);
        }
        task.dumpable = dumpable;
        Ok(())
    }

    fn prctl_get_no_new_privs(&self) -> bool {
        let graph = self.runtime.graph.lock();
        graph
            .owner
            .task(self.key)
            .map(|t| t.no_new_privs)
            .unwrap_or(false)
    }

    fn prctl_set_no_new_privs(&mut self, no_new_privs: bool) -> Result<(), i64> {
        let mut graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task_mut(self.key)
            .map_err(|_| carrick_personality_linux::identity::ESRCH)?;
        if task.no_new_privs && !no_new_privs {
            return Err(carrick_personality_linux::identity::EPERM);
        }
        task.no_new_privs = no_new_privs;
        Ok(())
    }

    fn prctl_get_child_subreaper(&self) -> bool {
        let graph = self.runtime.graph.lock();
        graph
            .owner
            .task(self.key)
            .map(|t| t.child_subreaper)
            .unwrap_or(false)
    }

    fn prctl_set_child_subreaper(&mut self, subreaper: bool) {
        let mut graph = self.runtime.graph.lock();
        if let Ok(task) = graph.owner.task_mut(self.key) {
            task.child_subreaper = subreaper;
        }
    }
}

impl<'r, 'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    carrick_personality_linux::sysinfo::ProcessSysinfoVenue
    for NativeProcessEntry<'r, 'a, M, C, S>
{
    fn get_uts(&self) -> carrick_personality_linux::sysinfo::LinuxUtsname {
        self.runtime.graph.lock().uts
    }

    fn can_set_hostname(&self) -> Result<(), i64> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
        let creds = task
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
        if !creds.is_admin_privileged() {
            return Err(carrick_personality_linux::sysinfo::EPERM);
        }
        Ok(())
    }

    fn set_hostname(&mut self, name: &[u8]) -> Result<(), i64> {
        self.can_set_hostname()?;
        self.runtime.graph.lock().uts.set_nodename(name);
        Ok(())
    }

    fn can_set_domainname(&self) -> Result<(), i64> {
        self.can_set_hostname()
    }

    fn set_domainname(&mut self, name: &[u8]) -> Result<(), i64> {
        self.can_set_hostname()?;
        self.runtime.graph.lock().uts.set_domainname(name);
        Ok(())
    }

    fn get_rlimit(
        &self,
        resource: usize,
    ) -> Result<carrick_personality_linux::sysinfo::LinuxRlimit, i64> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
        task.rlimits
            .get(resource)
            .ok_or(carrick_personality_linux::sysinfo::EINVAL)
    }

    fn set_rlimit(
        &mut self,
        resource: usize,
        limit: carrick_personality_linux::sysinfo::LinuxRlimit,
    ) -> Result<(), i64> {
        self.prlimit64(0, resource, Some(limit)).map(|_| ())
    }

    #[inline(never)]
    fn prlimit64(
        &mut self,
        pid: i32,
        resource: usize,
        new_limit: Option<carrick_personality_linux::sysinfo::LinuxRlimit>,
    ) -> Result<carrick_personality_linux::sysinfo::LinuxRlimit, i64> {
        if new_limit.is_some_and(|limit| limit.rlim_cur > limit.rlim_max) {
            return Err(carrick_personality_linux::sysinfo::EINVAL);
        }
        let mut graph = self.runtime.graph.lock();
        let caller = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
        let caller_pid = caller.metadata().namespace_pid;
        let caller_creds = caller
            .credentials_for(self.calling_tid)
            .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
        let caller_privileged = caller_creds.is_resource_privileged();
        let caller_ruid = caller_creds.ruid;
        let caller_rgid = caller_creds.rgid;

        let target_pid = if pid == 0 { caller_pid } else { pid as u32 };
        let is_self_process = target_pid == caller_pid || caller.has_thread(target_pid);
        if !is_self_process && !caller_privileged {
            let target = graph
                .owner
                .find_task_by_pid(target_pid)
                .filter(|row| row.native().resources().control.visible_tid().is_some())
                .ok_or(carrick_personality_linux::sysinfo::ESRCH)?;
            let target_creds = target
                .credentials_for(target.metadata().namespace_pid)
                .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
            if !target_creds.allows_prlimit_from(caller_ruid, caller_rgid) {
                return Err(carrick_personality_linux::sysinfo::EPERM);
            }
        }

        let target = if is_self_process {
            graph
                .owner
                .task_mut(self.key)
                .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?
        } else {
            graph
                .owner
                .find_task_by_pid_mut(target_pid)
                .filter(|row| row.native().resources().control.visible_tid().is_some())
                .ok_or(carrick_personality_linux::sysinfo::ESRCH)?
        };
        let old = target
            .rlimits
            .get(resource)
            .ok_or(carrick_personality_linux::sysinfo::EINVAL)?;
        if let Some(limit) = new_limit {
            if limit.rlim_cur > limit.rlim_max {
                return Err(carrick_personality_linux::sysinfo::EINVAL);
            }
            if limit.rlim_max > old.rlim_max && !caller_privileged {
                return Err(carrick_personality_linux::sysinfo::EPERM);
            }
            target.rlimits.set(resource, limit);
        }
        Ok(old)
    }

    fn umask(&mut self, mask: u32) -> u32 {
        let mut graph = self.runtime.graph.lock();
        let Ok(task) = graph.owner.task_mut(self.key) else {
            return 0o022;
        };
        let old = task.umask;
        task.umask = mask & 0o777;
        old
    }

    fn sysinfo(&self) -> carrick_personality_linux::sysinfo::LinuxSysinfo {
        carrick_personality_linux::sysinfo::LinuxSysinfo::default_info()
    }

    fn getrusage(&self, who: i32) -> Result<carrick_personality_linux::sysinfo::LinuxRusage, i64> {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_personality_linux::sysinfo::ESRCH)?;
        let usage = match who {
            0 | 1 => task.native().own_rusage(),
            -1 => task.children_rusage(),
            _ => return Err(carrick_personality_linux::sysinfo::EINVAL),
        };
        let mut ru = carrick_personality_linux::sysinfo::LinuxRusage::zeroed();
        ru.ru_utime.tv_sec = usage.user_time.as_secs() as i64;
        ru.ru_utime.tv_usec = usage.user_time.subsec_micros() as i64;
        ru.ru_stime.tv_sec = usage.system_time.as_secs() as i64;
        ru.ru_stime.tv_usec = usage.system_time.subsec_micros() as i64;
        Ok(ru)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::drop_non_drop
)]
mod tests {
    #[test]
    fn cpl0_clear_tid_dependency_names_the_arm_reference() {
        let design = include_str!("../../../../docs/design/arm-ring-first-flip.md");
        assert!(design.contains("shared-cpl0-thread-exit-clear-tid"));
        assert!(
            design.contains("exit_of_a_born_thread_clears_cleartid_wakes_the_joiner_and_runs_it")
        );
    }
    #[test]
    fn unsupported_exec_has_no_completion_surface() {
        let source = include_str!("native_process_runtime.rs");
        let production = source.split("mod tests {").next().unwrap();
        assert!(!production.contains(concat!("fn exec", "_completed(")));
        assert!(
            include_str!("../../../../docs/design/arm-ring-first-flip.md")
                .contains("shared-owner-exec-completion")
        );
    }

    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa};
    use carrick_sched_core::ParkedContextWords;
    struct Physical<'a> {
        zone: &'a ZoneTables<ParkedContextWords>,
        page: &'a ThreadLifecyclePage,
        controls: &'a [ThreadControlSlot],
        copies: Vec<LinuxWaitStatus>,
        refuse_copy: bool,
    }
    impl<'a> NativeProcessService<'a, ParkedContextWords> for Physical<'a> {
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
        fn quarantine_fork(
            &mut self,
            _: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm, ParkedContextWords>,
        ) {
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
    fn actual_shared_root_admission_accepts_arm_asid_and_rejects_stale_binding() {
        for (arm, register, saved_generation, accepted) in [
            (true, 0xabcd_0000_0000_1000, 1, true),
            (true, 0xabcd_0000_0000_2000, 1, false),
            (true, 0xabcd_0000_0000_1000, 2, false),
            (false, 0x1000, 1, true),
            (false, 0x2000, 1, false),
            (false, 0x1000, 2, false),
            (false, 0xabcd_0000_0000_1000, 1, false),
            (false, 0x1001, 1, false),
        ] {
            let layout =
                std::alloc::Layout::new::<ZoneTables<carrick_sched_core::Aarch64ParkedContext>>();
            // SAFETY: the aligned allocation owns the complete zero-valid compact zone.
            let zone = unsafe {
                let ptr = std::alloc::alloc_zeroed(layout)
                    .cast::<ZoneTables<carrick_sched_core::Aarch64ParkedContext>>();
                assert!(!ptr.is_null());
                Box::from_raw(ptr)
            };
            let page = Box::new(ThreadLifecyclePage::new());
            let control = Box::new(ThreadControlSlot::new());
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
            let space = zone.spaces.publish_closed(1, register, 0).unwrap();
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
            let mut native = carrick_sched_core::ThreadCtx::ZERO;
            native.x[0] = 99;
            native.tpidr_el0 = 0x4567;
            native.v[3] = u128::MAX;
            let saved = carrick_sched_core::Aarch64ParkedContext::from_register(
                native,
                0x1000,
                1,
                saved_generation,
            );
            let source = BornInZoneSource { zone: &zone, slot };
            let admitted = if arm {
                NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::owner_mmu::Aarch64Mmu>(
                    source, &task, &page, &control, address, address, saved,
                )
            } else {
                NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                    source, &task, &page, &control, address, address, saved,
                )
            };
            if accepted {
                let runtime = admitted.expect("the ARM ASID is not part of the root GPA");
                let graph = runtime.graph.lock();
                let retained = graph.owner.task(graph.root_key).unwrap().context();
                assert_eq!(retained.native, native);
            } else {
                assert!(matches!(admitted, Err(NativeProcessError::Stale)));
            }
        }
    }
    #[test]
    fn actual_compact_root_can_exit_before_its_first_park() {
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
        assert!(matches!(
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            ),
            Err(NativeProcessError::Invalid)
        ));
        assert_eq!(page.live(), 2, "admission must not remove a live member");
        page.release_live(1).unwrap(); // fixture settles its bootstrap census
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
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
        assert!(matches!(
            entry.exit_group(9),
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
        assert_eq!(
            entry.take_root_exit(),
            Some(LinuxWaitStatus::from_wait_encoding(9 << 8))
        );
        assert!(entry.take_handoff_receipt().is_some());
        assert_eq!(page.live(), 0);
        assert!(zone.slot(slot).host_record().is_none());
        assert!(zone.slot(slot).current().is_none());
        assert_eq!(zone.record(home).claim(), carrick_sched_core::Claim::Free);
    }

    #[test]
    fn exit_group_holds_terminal_custody_until_pre_live_claim_settles() {
        for (claim_live, wake_failure) in [(false, false), (true, false), (false, true)] {
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
            assert!(matches!(
                NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                    source,
                    &task,
                    &page,
                    &control,
                    address,
                    address,
                    words(address),
                ),
                Err(NativeProcessError::Invalid)
            ));
            assert_eq!(page.live(), 2, "admission must not remove a live member");
            page.release_live(1).unwrap(); // fixture settles its bootstrap census
            let runtime =
                NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
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
            page.stock(
                0,
                EntryIdentity {
                    tid: 42,
                    visible_tid: 42,
                    thread_serial: 102,
                    uid_credit: 0,
                },
            )
            .unwrap();
            let claim = page.claim_any().unwrap();
            if claim_live {
                assert_eq!(page.thread_born(), Some(2));
            }
            assert!(
                matches!(entry.exit_group(9), LifecycleOutcome::Transferred { .. }),
                "exit must suspend, never return guest EAGAIN"
            );
            assert_eq!(page.gate(), carrick_el1_abi::GateState::Closed);
            assert_eq!(page.live(), if claim_live { 2 } else { 1 });
            assert!(entry.take_run_failure().is_none());
            assert!(entry.take_root_exit().is_none());
            assert!(entry.take_handoff_receipt().is_some());
            assert_eq!(zone.slot(slot).queued(), 0);
            assert_eq!(
                entry.thread_spawned(41, 42, &mut || panic!("terminal close admitted Born")),
                Err(-11)
            );
            if claim_live {
                assert_eq!(page.try_exit(), Ok(1));
            }
            page.unclaim(claim).unwrap();
            // Claim owners deliver their settlement only after rollback is complete.
            // Direct hook invocation models that production lifecycle notification.
            if wake_failure {
                let channel = runtime
                    .graph
                    .lock()
                    .pending_exit
                    .get(&entry.key)
                    .unwrap()
                    .channel
                    .clone();
                let guard = zone
                    .lock(
                        ZoneTables::<ParkedContextWords>::bucket_of_with_context(
                            channel.mm,
                            WaitChannel::address(&channel),
                        ),
                        &BoundedSpin(LOCK_SPINS),
                    )
                    .unwrap();
                assert_eq!(entry.lifecycle_admission_settled(), Err(-11));
                assert_eq!(
                    entry.take_run_failure(),
                    Some(carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody)
                );
                assert!(entry.take_root_exit().is_none());
                assert_eq!(zone.slot(slot).queued(), 0);
                assert_eq!(page.live(), 1);
                assert!(runtime.graph.lock().pending_exit.contains_key(&entry.key));
                drop(guard);
                continue;
            }
            entry.lifecycle_admission_settled().unwrap();
            assert_eq!(zone.slot(slot).queued(), 1);
            let channel = runtime
                .graph
                .lock()
                .pending_exit
                .get(&entry.key)
                .unwrap()
                .channel
                .clone();
            let published = channel.generation.generation();
            entry.lifecycle_admission_settled().unwrap();
            assert_eq!(
                channel.generation.generation(),
                published,
                "wake custody has one publisher"
            );
            assert_eq!(zone.slot(slot).queued(), 1);
            assert!(matches!(
                page.claim_any(),
                Err(carrick_el1_abi::TransitionError::GateClosed(_))
            ));
            assert!(
                matches!(entry.fork(), LifecycleOutcome::Returned { result, .. } if result.raw() == -11)
            );
            drop(entry);
            let selected = zone.switch_in_full(slot).unwrap();
            assert_eq!(selected.record, home);
            let mut entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            assert!(matches!(
                entry.resume_pending_lifecycle().unwrap(),
                Some(LifecycleOutcome::Transferred { .. })
            ));
            assert_eq!(
                entry.take_root_exit(),
                Some(LinuxWaitStatus::from_wait_encoding(9 << 8))
            );
            assert!(entry.take_handoff_receipt().is_some());
            assert_eq!(page.live(), 0);
            assert_eq!(zone.slot(slot).queued(), 0);
            assert_eq!(zone.record(home).claim(), carrick_sched_core::Claim::Free);
        }
    }
    #[test]
    fn clone_live_membership_blocks_exit_between_graph_unlock_and_enqueue() {
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
        assert!(matches!(
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            ),
            Err(NativeProcessError::Invalid)
        ));
        assert_eq!(page.live(), 2, "admission must not remove a live member");
        page.release_live(1).unwrap(); // fixture settles its bootstrap census
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
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
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        // An admitted clone claim must also block the terminal transaction
        // before it has incremented the live count.
        page.stock(
            0,
            carrick_el1_abi::EntryIdentity {
                tid: 42,
                visible_tid: 42,
                thread_serial: 102,
                uid_credit: 0,
            },
        )
        .unwrap();
        let claim = page.claim_any().unwrap();
        assert_eq!(page.thread_born(), Some(2));
        let child = zone
            .alloc_record(ThreadIdentity {
                tid: 42,
                serial: 102,
                mm: 1,
                file_table: 5,
                generation: 0,
                affinity: 1,
                lifecycle_page: &*page as *const _ as u64,
                control_slot: &child_controls[1] as *const _ as u64,
            })
            .unwrap();
        let child_ref = zone.record_ref(child);
        let mut claim = Some(claim);
        entry
            .thread_spawned(41, 42, &mut || {
                page.record_born(
                    claim.take().unwrap(),
                    carrick_el1_abi::BornRecord {
                        caller_task: 41,
                        caller_serial: 101,
                        clone_flags: 0,
                        clear_child_tid: 0,
                        blocked: carrick_el1_abi::BlockedMask(0),
                    },
                )
                .unwrap();
                Ok(())
            })
            .unwrap();
        // The child owns Born membership but has not been enqueued yet.
        // Group cancellation is not wired: fail the run with typed custody,
        // preserving graph membership and MM ownership rather than guest errno.
        assert_eq!(zone.slot(slot).queued(), 0);
        assert!(matches!(
            entry.exit_owned(9),
            Ok(LifecycleOutcome::Transferred { .. })
        ));
        assert_eq!(
            entry.take_run_failure(),
            Some(carrick_el1_abi::NativeRunFailureReason::X86GroupExitCustody)
        );
        assert!(entry.take_handoff_receipt().is_some());
        assert!(entry.take_root_exit().is_none());
        assert!(entry.has_thread(42));
        assert_eq!(page.live(), 2);
        assert_eq!(zone.record(child).claim(), carrick_sched_core::Claim::Free);
        assert!(runtime.graph.lock().owner.task(entry.key).is_ok());
        assert_eq!(zone.record_ref(child), child_ref);
        assert_eq!(zone.record(child).identity().tid, 42);
        assert_eq!(page.state(0).unwrap().1, carrick_el1_abi::EntryState::Born);
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
        page.release_live(1).unwrap(); // fixture settles its bootstrap census
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
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
        assert_eq!(
            child_identity.file_table, 5,
            "ARM fork inherits the shared file table"
        );
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
    fn activate<'a>(
        runtime: &NativeProcessRuntime<'a, AddressContext<RootGpa>, ParkedContextWords>,
        source: BornInZoneSource<'a, ParkedContextWords>,
        task: &CurrentTask,
        key: TaskKey,
    ) {
        let graph = runtime.graph.lock();
        let row = graph.owner.task(key).unwrap();
        let resources = row.native().resources();
        let zone = source.zone;
        assert_eq!(
            zone.switch_in_full(source.slot).unwrap().record,
            resources.record.id
        );
        zone.install_space(source.slot, resources.address.mm.raw().get())
            .unwrap();
        let identity = zone.record(resources.record.id).identity();
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(key.id.raw()),
            key.serial.raw(),
            identity.file_table,
        );
        task.mm
            .key
            .store(resources.address.mm.raw().get(), Ordering::Release);
        task.mm
            .thread_generation
            .store(identity.serial, Ordering::Release);
        task.publish_visible_pid(row.metadata().namespace_pid);
        task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
    }
    #[test]
    fn blocked_adopter_wait_resumes_with_an_inherited_zombie() {
        for depth_count in [2, 3] {
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
            page.release_live(1).unwrap(); // fixture settles its bootstrap census
            let runtime =
                NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
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
            let descendant_pages = [ThreadLifecyclePage::new(), ThreadLifecyclePage::new()];
            let descendant_controls: [[ThreadControlSlot; 9]; 2] =
                core::array::from_fn(|_| core::array::from_fn(|_| ThreadControlSlot::new()));
            let mut actors = vec![parent];
            for depth in 0..depth_count {
                let current = *actors.last().unwrap();
                let row_address = runtime
                    .graph
                    .lock()
                    .owner
                    .task(current)
                    .unwrap()
                    .native()
                    .resources()
                    .address;
                let mut entry = runtime
                    .enter(source, &task, words(row_address), &mut service)
                    .unwrap();
                let LifecycleOutcome::Returned { result, .. } = entry.fork() else {
                    panic!("fork")
                };
                let next = runtime
                    .namespace_child_key(current, result.raw() as u32)
                    .unwrap();
                assert!(matches!(
                    entry.wait4(
                        ProcessWaitPid::from_syscall_argument(u64::MAX),
                        UserVa::new(0x8000),
                        LinuxWaitOptions::empty(),
                        UserVa::new(0)
                    ),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(entry.take_handoff_receipt().is_some());
                actors.push(next);
                activate(&runtime, source, &task, next);
                if depth + 1 < depth_count {
                    service.page = &descendant_pages[depth];
                    service.controls = &descendant_controls[depth];
                }
            }
            let zombie = actors[depth_count];
            let exiting = actors[depth_count - 1];
            let direct_parent = actors[1];
            let root_channel = runtime
                .graph
                .lock()
                .owner
                .task(parent)
                .unwrap()
                .native()
                .resources()
                .channel
                .clone()
                .unwrap();
            let before = root_channel.generation.generation();
            {
                let address = runtime
                    .graph
                    .lock()
                    .owner
                    .task(zombie)
                    .unwrap()
                    .native()
                    .resources()
                    .address;
                let mut entry = runtime
                    .enter(source, &task, words(address), &mut service)
                    .unwrap();
                assert!(matches!(
                    entry.exit_group(7),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(entry.take_handoff_receipt().is_some());
            }
            activate(&runtime, source, &task, exiting);
            {
                let address = runtime
                    .graph
                    .lock()
                    .owner
                    .task(exiting)
                    .unwrap()
                    .native()
                    .resources()
                    .address;
                let mut entry = runtime
                    .enter(source, &task, words(address), &mut service)
                    .unwrap();
                assert!(matches!(
                    entry.exit_group(8),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(entry.take_handoff_receipt().is_some());
            }
            assert_eq!(
                root_channel.generation.generation().raw(),
                before.raw() + 1,
                "inherited zombie must wake the already blocked adopter exactly once"
            );
            if depth_count == 3 {
                // Hold the other woken parent at the host boundary so this assertion
                // resumes the adopter before any additional exit can wake it.
                let direct_record = runtime
                    .graph
                    .lock()
                    .owner
                    .task(direct_parent)
                    .unwrap()
                    .native()
                    .resources()
                    .record;
                assert!(matches!(
                    zone.claim_for_host(
                        direct_record,
                        None,
                        Handback::Cancelled,
                        &BoundedSpin(LOCK_SPINS)
                    ),
                    carrick_sched_core::HostClaim::Claimed
                ));
            }
            activate(&runtime, source, &task, parent);
            let mut entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            let Some(LifecycleOutcome::Returned { result, .. }) = entry.resume_pending_wait()
            else {
                panic!("adopter resume")
            };
            if depth_count == 2 {
                // The original child has the lower PID and remains eligible.
                assert_eq!(result.raw(), 42);
                let LifecycleOutcome::Returned { result, .. } = entry.wait4(
                    ProcessWaitPid::from_syscall_argument(u64::MAX),
                    UserVa::new(0x8000),
                    LinuxWaitOptions::empty(),
                    UserVa::new(0),
                ) else {
                    panic!("inherited zombie return")
                };
                assert_eq!(result.raw(), 43);
            } else {
                assert_eq!(result.raw(), 44);
            }
            assert_eq!(
                service.copies.last(),
                Some(&LinuxWaitStatus::from_wait_encoding(7 << 8))
            );
        }
    }

    #[test]
    fn two_threads_raw_setresuid_on_one_leaves_other_unchanged() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        use carrick_personality_linux::identity::ProcessIdentityVenue;
        use carrick_personality_linux::lifecycle::ProcessNative;

        entry.set_calling_tid(999);
        assert_eq!(
            entry.get_uids(),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        assert_eq!(
            entry.get_gids(),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        assert_eq!(
            entry.get_groups_count(),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        assert_eq!(
            entry.set_fsuid(1234),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        assert_eq!(
            entry.set_fsgid(1234),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        let mut groups = alloc::vec![1234];
        assert_eq!(
            entry.get_groups(&mut groups),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        assert_eq!(groups, alloc::vec![1234]);
        let mut published = false;
        assert_eq!(
            entry.thread_spawned(999, 88, &mut || {
                published = true;
                Ok(())
            }),
            Err(carrick_personality_linux::identity::ESRCH)
        );
        assert!(!published);
        assert_eq!(entry.thread_spawned(41, 88, &mut || Err(-14)), Err(-14));
        assert!(!entry.has_thread(88));
        // Comm per thread
        let mut comm_leader = [0u8; 16];
        let mut comm_worker = [0u8; 16];
        entry.set_calling_tid(41);
        entry.prctl_set_name(b"leader\0\0\0\0\0\0\0\0\0\0");
        entry.thread_spawned(41, 42, &mut || Ok(())).unwrap();
        entry.set_calling_tid(42);
        entry.prctl_set_name(b"worker\0\0\0\0\0\0\0\0\0\0");

        entry.set_calling_tid(41);
        entry.prctl_get_name(&mut comm_leader).unwrap();
        assert_eq!(&comm_leader[..7], b"leader\0");

        entry.set_calling_tid(42);
        entry.prctl_get_name(&mut comm_worker).unwrap();
        assert_eq!(&comm_worker[..7], b"worker\0");

        // Calling from thread 42: change UIDs to 1000
        entry.set_calling_tid(42);
        entry
            .set_resuid(Some(1000), Some(1000), Some(1000))
            .unwrap();
        assert_eq!(entry.get_uids().unwrap(), (1000, 1000, 1000, 1000));

        // Calling from thread 41 (leader): UIDs must still be root (0, 0, 0, 0)
        entry.set_calling_tid(41);
        assert_eq!(
            entry.get_uids().unwrap(),
            (0, 0, 0, 0),
            "thread 1 credentials must remain unchanged when thread 2 changes its UID"
        );

        // Spawn thread 43 from thread 42: inherits thread 42's credentials and comm
        entry.thread_spawned(42, 43, &mut || Ok(())).unwrap();
        entry.set_calling_tid(43);
        assert_eq!(entry.get_uids().unwrap(), (1000, 1000, 1000, 1000));
        let mut comm_child = [0u8; 16];
        entry.prctl_get_name(&mut comm_child).unwrap();
        assert_eq!(&comm_child[..7], b"worker\0");

        // Fork from thread 42: child process inherits thread 42's credentials and comm
        entry.set_calling_tid(42);
        let child_pid = entry.fork_owned().expect("fork from thread 42 succeeds");
        drop(entry);

        let graph = runtime.graph.lock();
        let child_task = graph
            .owner
            .find_task_by_pid(child_pid)
            .expect("child task found");
        let child_creds = child_task.credentials_for(child_pid).unwrap();
        assert_eq!(
            (
                child_creds.ruid.raw(),
                child_creds.euid.raw(),
                child_creds.suid.raw(),
                child_creds.fsuid.raw(),
            ),
            (1000, 1000, 1000, 1000)
        );
        let child_comm = child_task.comm_for(child_pid).unwrap();
        assert_eq!(&child_comm[..7], b"worker\0");
    }

    #[test]
    fn thread_exit_removes_thread_state_and_stays_bounded() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let key = TaskKey {
            id: TaskId::from_abi_positive(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();

        // Spawn 100 short-lived threads and exit them.
        for i in 0..100 {
            let tid = 1000 + i;
            entry.thread_spawned(41, tid, &mut || Ok(())).unwrap();
            entry.thread_exited(tid);
        }

        drop(entry);
        let graph = runtime.graph.lock();
        let t = graph.owner.task(key).unwrap();
        // The list must stay bounded to just the leader thread.
        assert_eq!(t.threads.threads.len(), 1);
        assert_eq!(t.has_thread(1050), false);
    }

    #[test]
    fn non_leader_credential_changes_and_calling_thread_authority() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let key = TaskKey {
            id: TaskId::from_abi_positive(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        use carrick_personality_linux::identity::ProcessIdentityVenue;

        // 1. Unregistered TID lookup must be an explicit error, not silent fallback to leader
        {
            let graph = runtime.graph.lock();
            let t = graph.owner.task(key).unwrap();
            assert_eq!(
                t.credentials_for(9999),
                Err(carrick_personality_linux::identity::ESRCH)
            );
        }

        // 2. Caller TID 9999 attempting modify_credentials returns ESRCH
        entry.set_calling_tid(9999);
        let mut missing_name = [0xa5; 16];
        assert_eq!(
            entry.prctl_get_name(&mut missing_name),
            Err(carrick_personality_linux::identity::IdentityReadError::MissingThread)
        );
        assert_eq!(
            missing_name, [0xa5; 16],
            "missing comm must not manufacture an empty name"
        );

        assert_eq!(
            entry.set_uid(1000),
            Err(carrick_personality_linux::identity::ESRCH)
        );

        // 3. Spawning thread 42 from leader 41
        entry.set_calling_tid(41);
        entry.thread_spawned(41, 42, &mut || Ok(())).unwrap();

        // 4. Thread 42 changes credentials to uid 1000
        entry.set_calling_tid(42);
        entry.set_uid(1000).unwrap();
        assert_eq!(entry.get_uids().unwrap().0, 1000);

        // Leader 41 credentials remain root (0)
        entry.set_calling_tid(41);
        assert_eq!(entry.get_uids().unwrap().0, 0);

        // 5. Thread 43 spawned from thread 42 inherits thread 42 credentials (uid 1000)
        entry.thread_spawned(42, 43, &mut || Ok(())).unwrap();
        entry.set_calling_tid(43);
        assert_eq!(entry.get_uids().unwrap().0, 1000);

        // 6. Spawning from unknown caller TID 8888 fails with ESRCH
        {
            let mut graph = runtime.graph.lock();
            let t = graph.owner.task_mut(key).unwrap();
            assert_eq!(
                t.spawn_thread(8888, 44),
                Err(carrick_personality_linux::identity::ESRCH)
            );
        }
    }

    #[test]
    fn capset_restricted_to_pid_zero_and_caller_own_tid() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        use carrick_personality_linux::identity::ProcessIdentityVenue;

        entry.set_calling_tid(41);
        entry.thread_spawned(41, 42, &mut || Ok(())).unwrap();

        // From thread 42:
        entry.set_calling_tid(42);
        let caps = entry.capget(0).unwrap();

        // capset on another thread (leader 41) must fail with EPERM
        assert_eq!(
            entry.capset(41, caps.clone()),
            Err(carrick_personality_linux::identity::EPERM)
        );
        // capset on negative pid must fail with EPERM
        assert_eq!(
            entry.capset(-1, caps.clone()),
            Err(carrick_personality_linux::identity::EPERM)
        );
        // capset on own tid 42 and pid 0 must succeed
        assert_eq!(entry.capset(42, caps.clone()), Ok(()));
        assert_eq!(entry.capset(0, caps), Ok(()));
    }

    #[test]
    fn getppid_returns_zero_when_parent_outside_pid_namespace() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        use carrick_personality_linux::identity::ProcessIdentityVenue;

        let parent_key = TaskKey {
            id: TaskId::from_abi_positive(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let parent_record = runtime
            .graph
            .lock()
            .owner
            .task(parent_key)
            .unwrap()
            .native()
            .resources()
            .record;

        entry.set_calling_tid(41);
        let child_pid = entry.fork_owned().expect("fork child succeeds") as i32;
        drop(entry);

        zone.requeue_preempted(slot, parent_record.id);
        let child_key = {
            let graph = runtime.graph.lock();
            graph
                .owner
                .find_task_by_pid(child_pid as u32)
                .unwrap()
                .key()
        };
        let (child_address, child_words, child_record) = {
            let graph = runtime.graph.lock();
            let row = graph.owner.task(child_key).unwrap();
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
            carrick_el1_abi::El1TaskId::from_linux_tid(child_key.id.raw()),
            child_key.serial.raw(),
            child_identity.file_table,
        );
        task.mm
            .key
            .store(child_address.mm.raw().get(), Ordering::Release);
        task.mm
            .thread_generation
            .store(child_identity.serial, Ordering::Release);
        task.publish_visible_pid(child_pid as u32);
        task.publish_lifecycle(child_identity.lifecycle_page, child_identity.control_slot);

        let child_entry = runtime
            .enter(source, &task, child_words, &mut service)
            .unwrap();

        // 1. Same namespace: child get_ppid returns parent's pid (41)
        assert_eq!(child_entry.get_ppid(), 41);

        // 2. Parent placed outside caller's pid namespace: get_ppid returns 0
        {
            let mut graph = runtime.graph.lock();
            let parent_task = graph.owner.task_mut(parent_key).unwrap();
            parent_task.metadata_mut().container =
                VisibleNamespace::new(NonZeroU32::new(99).unwrap(), NonZeroU32::new(1).unwrap());
        }
        assert_eq!(child_entry.get_ppid(), 0);
    }

    #[test]
    fn get_robust_list_foreign_nonleader_dispatch_checks() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        entry.set_calling_tid(41);

        // 1. Calling thread itself is permitted
        use carrick_personality_linux::lifecycle::ProcessNative;
        assert_eq!(
            entry.read_robust_list(41, &mut |_, _| None).map(|_| ()),
            Ok(())
        );

        // 2. Sibling thread in caller's thread group is permitted without special capability
        entry.thread_spawned(41, 50, &mut || Ok(())).unwrap();
        assert!(entry.has_thread(50));
        assert_eq!(
            entry.read_robust_list(50, &mut |_, _| None),
            Err(carrick_personality_linux::identity::ESRCH)
        );

        // 3. Non-existent PID returns ESRCH
        assert_eq!(
            entry.read_robust_list(999, &mut |_, _| None).map(|_| ()),
            Err(carrick_personality_linux::identity::ESRCH)
        );

        // 4. Another process without ptrace capability returns EPERM
        let child_pid = entry.fork_owned().expect("fork child succeeds") as u32;
        // Make caller unprivileged (drop CAP_SYS_PTRACE, uid 1000)
        use carrick_personality_linux::identity::ProcessIdentityVenue;
        entry.set_uid(1000).unwrap();
        assert_eq!(
            entry
                .read_robust_list(child_pid, &mut |_, _| None)
                .map(|_| ()),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            let credentials = graph
                .owner
                .task(entry.key)
                .unwrap()
                .credentials_for(41)
                .unwrap()
                .clone();
            let peer = graph.owner.find_task_by_pid_mut(child_pid).unwrap();
            *peer.credentials_for_mut(child_pid).unwrap() = credentials;
            peer.spawn_thread(child_pid, 987).unwrap();
        }
        assert_eq!(
            entry
                .read_robust_list(child_pid, &mut |_, _| None)
                .map(|_| ()),
            Ok(())
        );
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| None),
            Err(carrick_personality_linux::identity::ESRCH)
        );
        child_controls[1].set_robust_list(0xbeef, 24);
        assert_eq!(
            entry.read_robust_list(child_pid, &mut |_, _| None),
            Ok((0xbeef, 24))
        );
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| None),
            Err(carrick_personality_linux::identity::ESRCH)
        );
        let peer_entry = child_page
            .stock(
                1,
                carrick_el1_abi::EntryIdentity {
                    tid: 987,
                    visible_tid: 987,
                    thread_serial: 987,
                    uid_credit: 1,
                },
            )
            .unwrap();
        child_page
            .bind_control_address(peer_entry, &child_controls[2] as *const _ as u64)
            .unwrap();
        child_controls[2].reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, peer_entry);
        assert!(child_controls[2].publish_visible_tid(987));
        use carrick_el1_abi::Lifecycle;
        child_page.thread_born().unwrap();
        let born = child_page
            .record_born(
                child_page.claim(peer_entry).unwrap(),
                carrick_el1_abi::BornRecord {
                    caller_task: u64::from(child_pid),
                    caller_serial: 1,
                    clone_flags: 0,
                    clear_child_tid: 0,
                    blocked: carrick_el1_abi::BlockedMask(0),
                },
            )
            .unwrap();
        child_page.publish(born).unwrap();
        child_controls[2].set_robust_list(0xcafe, 24);
        assert_eq!(
            entry.read_robust_list(987, &mut |page, reference| {
                assert!(core::ptr::eq(page, &*child_page));
                assert_eq!(reference, peer_entry);
                Some(child_controls[2].robust_list())
            }),
            Ok((0xcafe, 24))
        );
        // PTRACE_MODE_READ_FSCREDS compares filesystem credentials, not the
        // caller's real ids. Read a peer nonleader through the shared router.
        entry
            .update_calling_creds(&mut |c| {
                c.fsuid = carrick_sched_core::process::TaskUid::new(2000);
                c.fsgid = carrick_sched_core::process::TaskGid::new(2000);
                Ok(())
            })
            .unwrap();
        {
            let mut graph = runtime.graph.lock();
            let peer = graph.owner.find_task_by_pid_mut(child_pid).unwrap();
            for tid in [child_pid, 987] {
                let c = peer.credentials_for_mut(tid).unwrap();
                c.ruid = carrick_sched_core::process::TaskUid::new(2000);
                c.euid = c.ruid;
                c.suid = c.ruid;
                c.rgid = carrick_sched_core::process::TaskGid::new(2000);
                c.egid = c.rgid;
                c.sgid = c.rgid;
            }
        }
        struct RetainedVenue<'a> {
            page: &'a ThreadLifecyclePage,
            control: &'a ThreadControlSlot,
            peer: NativeLifecycleResources<'a>,
            foreign_reads: core::cell::Cell<u32>,
        }
        impl super::super::thread_setup::LifecycleVenue for RetainedVenue<'_> {
            fn thread<'a>(
                &'a self,
                _: &'a CurrentTask,
            ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
                Some(carrick_personality_linux::thread::LifecycleThread {
                    page: self.page,
                    slot: self.control,
                })
            }
            fn born_slot(
                &self,
                page: &ThreadLifecyclePage,
                entry: EntryRef,
            ) -> Option<&ThreadControlSlot> {
                assert!(
                    core::ptr::eq(page, self.peer.page),
                    "foreign lifecycle page must reach born_slot"
                );
                self.foreign_reads.set(self.foreign_reads.get() + 1);
                let slot = self.peer.born_slot(entry)?;
                assert_eq!(page.control_address(entry), Some(slot as *const _ as u64));
                Some(slot)
            }
        }
        struct HostCopy;
        impl crate::file::UserCopy for HostCopy {
            fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
                false
            }
            fn copy_out(&mut self, address: u64, bytes: &[u8]) -> bool {
                // SAFETY: this fixture supplies live aligned u64 output words.
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
                }
                true
            }
        }
        let venue = RetainedVenue {
            page: &page,
            control: &control,
            peer: NativeLifecycleResources {
                page: &child_page,
                controls: &*child_controls,
            },
            foreign_reads: core::cell::Cell::new(0),
        };
        let mut head = 0_u64;
        let mut len = 0_u64;
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[0] = 987;
        frame.x[1] = &mut head as *mut u64 as u64;
        frame.x[2] = &mut len as *mut u64 as u64;
        frame.x[8] = carrick_syscall_abi::nr::GET_ROBUST_LIST.raw() as u64;
        let names = carrick_el1_abi::InotifyNameCache::new();
        let mut copy = HostCopy;
        let mut pending: super::super::dispatch::El1PendingFamilies<
            '_,
            _,
            super::super::sched::FakeCpu,
            super::super::sched::HardwareUserWord,
            _,
            ParkedContextWords,
        > = super::super::dispatch::El1PendingFamilies {
            handoff: None,
            lifecycle_user: Some(&mut copy),
            frame: &mut frame,
            counters: &carrick_el1_abi::Counters::new(),
            current_tasks: core::slice::from_ref(&task),
            fd_map: &[],
            object_table: &[],
            open_table: &[],
            inotify_table: &[],
            name_cache: &names,
            zone: None,
            ipc: None,
            lifecycle: Some(&venue),
            process: Some(&mut entry),
            source: Some(source),
            anonymous: None,
            cache_lookup: |_| core::ptr::null_mut(),
        };
        assert_eq!(
            carrick_personality_linux::dispatch::dispatch(
                carrick_syscall_abi::nr::GET_ROBUST_LIST.raw() as u64,
                u64::MAX,
                &mut pending
            ),
            carrick_personality_linux::dispatch::CompletionRoute::Served
        );
        drop(pending);
        assert_eq!(
            frame.x[0] as i64, 0,
            "filesystem credential match must permit the peer read"
        );
        assert_eq!((head, len), (0xcafe, 24));
        assert_eq!(venue.foreign_reads.get(), 1);
        {
            let mut graph = runtime.graph.lock();
            graph
                .owner
                .find_task_by_pid_mut(child_pid)
                .unwrap()
                .dumpable = 0;
        }
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            let peer = graph.owner.find_task_by_pid_mut(child_pid).unwrap();
            peer.dumpable = 1;
            peer.credentials_for_mut(987).unwrap().cap_permitted =
                carrick_sched_core::process::LinuxCapabilitySet::CAP_SETUID;
        }
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            graph
                .owner
                .find_task_by_pid_mut(child_pid)
                .unwrap()
                .credentials_for_mut(987)
                .unwrap()
                .cap_permitted = carrick_sched_core::process::LinuxCapabilitySet::empty();
        }
        // A matching real uid cannot bypass mismatched filesystem credentials.
        entry
            .update_calling_creds(&mut |c| {
                c.ruid = carrick_sched_core::process::TaskUid::new(2000);
                c.rgid = carrick_sched_core::process::TaskGid::new(2000);
                c.fsuid = carrick_sched_core::process::TaskUid::new(1000);
                c.fsgid = carrick_sched_core::process::TaskGid::new(1000);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            let peer = graph.owner.find_task_by_pid_mut(child_pid).unwrap();
            *peer.credentials_for_mut(child_pid).unwrap() =
                carrick_sched_core::process::TaskCredentials::ROOT;
        }
        entry
            .update_calling_creds(&mut |c| {
                c.cap_effective = carrick_sched_core::process::LinuxCapabilitySet::CAP_SETUID;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            entry
                .read_robust_list(child_pid, &mut |_, _| None)
                .map(|_| ()),
            Err(carrick_personality_linux::identity::EPERM)
        );
        entry
            .update_calling_creds(&mut |c| {
                c.cap_effective = carrick_sched_core::process::LinuxCapabilitySet::CAP_SYS_PTRACE;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            entry.read_robust_list(child_pid, &mut |_, _| None),
            Ok((0xbeef, 24))
        );
        // A predecessor of a host-completed exec has lost its control stamp.
        // Peer queries must not expose its stale shared owner, even with caps.
        child_controls[1].retire_identity();
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::ESRCH)
        );
        assert_eq!(
            carrick_personality_linux::identity::ProcessIdentityVenue::set_pgid(
                &mut entry,
                child_pid as i32,
                child_pid as i32
            ),
            Err(carrick_personality_linux::identity::ESRCH)
        );
    }

    #[test]
    fn prlimit64_resolves_non_leader_tid_of_own_process() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
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
        let runtime =
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap();
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            refuse_copy: false,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        entry.set_calling_tid(41);

        // Spawn a non-leader thread TID 50 in caller process 41
        entry.thread_spawned(41, 50, &mut || Ok(())).unwrap();

        use carrick_personality_linux::sysinfo::ProcessSysinfoVenue;
        // Calling prlimit64 on non-leader TID 50 should resolve to own process limits (not ESRCH)
        let res = entry.prlimit64(50, 7, None);
        assert!(
            res.is_ok(),
            "prlimit64 on non-leader tid should succeed: {:?}",
            res
        );

        // Unprivileged caller on non-leader TID 50 also succeeds because it's own process
        use carrick_personality_linux::identity::ProcessIdentityVenue;
        entry.set_uid(1000).unwrap();
        let res_unpriv = entry.prlimit64(50, 7, None);
        assert!(
            res_unpriv.is_ok(),
            "prlimit64 unprivileged on own non-leader tid should succeed: {:?}",
            res_unpriv
        );

        // Calling prlimit64 on truly nonexistent TID 999 still returns ESRCH
        let res_missing = entry.prlimit64(999, 7, None);
        assert_eq!(res_missing, Err(carrick_personality_linux::sysinfo::ESRCH));
    }
}
