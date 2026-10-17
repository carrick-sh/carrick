//! Native process custody over the shared guest owner and compact zone.
//! Root admission adopts the existing execution incarnation as a local process
//! incarnation; it does not import a host TaskSerial or launcher credentials.
extern crate alloc;
use super::{
    native_process_custody::{ProcessResources, ProcessWake, RetainedProcessCustody},
    native_process_entry::{self, CopiedWaitOutcome, ForkTryError, PreparedFork, WaitWork},
    native_process_signals::{NativeExitSignals, NativeProcessSignals},
    process_owner::{GuestProcessOwner, GuestTask, GuestTaskMetadata, NativeProcessCustody},
};
use crate::lock::SpinLock;
use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, EntryHandoffReceipt, EntryIdentity, EntryRef, ExecutionBinding,
    Lifecycle, ThreadControlSlot, ThreadLifecyclePage,
};
use carrick_guest_arch::{AddressContext, MmGeneration, ProcessContext, RootGpa, UserVa};
use carrick_personality_linux::ipc::namespace::{
    IpcError, IpcNamespace, MsgrcvOutcome, MsgsndOutcome, SemopOutcome,
};
use carrick_personality_linux::lifecycle::LinuxWaitStatus;
use carrick_personality_linux::{
    abi::entry::SyscallResult,
    ipc::{
        IpcOutcome, LinuxMsginfo, LinuxMsqidDs, LinuxSembuf, LinuxSemidDs, LinuxSeminfo,
        MsgrcvResult, ProcessIpcVenue,
    },
    lifecycle::{
        LifecycleOutcome, LinuxWaitOptions, ProcessForkChildTid, ProcessNative, ProcessWaitPid,
    },
};
#[cfg(test)]
use carrick_sched_core::BoundedSpin;
use carrick_sched_core::object_wait::OwnerEntry;
use carrick_sched_core::process::{
    ChildExitSignal, TaskId, TaskIdentity, TaskKey, TaskRusage, TaskSerial, WaitTarget,
};
use carrick_sched_core::process::{
    birth::BirthAttachment,
    exit::ExitMember,
    identity_allocator::{
        ClaimKind, InternalIdentity, NamespaceState, SerialAllocator, VisibleIdentity,
        VisibleNamespace,
    },
    wait::{TaskWakeGeneration, WaitJobControl, WaitPrecheck, WaitQuery, WaitSelection},
};
use carrick_sched_core::{
    Handback, RecordRef, SlotId, ThreadIdentity, WakeEffects, Waker, ZoneTables,
};
use core::{
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

/// Outcome of re-entering the shared process owner after an ISA switches in
/// a record with retained lifecycle work.
pub enum NativeResume {
    NoPending,
    Returned(SyscallResult),
    Left(Option<LinuxWaitStatus>),
    Invalid,
}
static NATIVE_SUSPEND_MASKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
const LOCK_SPINS: u32 = 100_000;

fn signal_record_exists<C: ProcessContext>(zone: &ZoneTables<C>, record: RecordRef) -> bool {
    if zone.live(record).is_some() {
        return true;
    }
    let retained = zone.record(record.id);
    retained.incarnation() == record.incarnation
        && retained.claim() == carrick_sched_core::Claim::Free
        && retained.home().is_some_and(|slot| {
            zone.slot(slot).current().is_none() && zone.slot(slot).host_record() == Some(record.id)
        })
}

fn request_signal_reschedule<'a, C: ProcessContext, S: NativeProcessService<'a, C>>(
    zone: &ZoneTables<C>,
    service: &mut S,
    record: RecordRef,
) {
    if !signal_record_exists(zone, record) {
        return;
    }
    let owned = zone.record(record.id);
    let target = match owned.claim() {
        carrick_sched_core::Claim::OnCpu { slot, .. }
        | carrick_sched_core::Claim::OnCpuRequested { slot, .. } => Some(slot),
        carrick_sched_core::Claim::Free => owned.home(),
        _ => None,
    };
    if let Some(slot) = target {
        let mut effects = WakeEffects::default();
        effects.request_reschedule(slot);
        service.wake_effects(effects);
    }
}

fn publish_signal_channel<'a, C: ProcessContext, S: NativeProcessService<'a, C>>(
    zone: &'a ZoneTables<C>,
    slot: SlotId,
    service: &mut S,
    channel: &Arc<WaitChannel>,
    #[cfg(test)] probe: Option<&(dyn Fn(u32) + Sync)>,
) -> Result<(), NativeProcessError> {
    let address = WaitChannel::address(channel);
    let guard = zone.short_lock(
        ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
        &NativeBucketWait {
            lifetime: core::marker::PhantomData,
            #[cfg(test)]
            probe,
        },
    );
    channel
        .generation
        .publish()
        .map_err(|_| NativeProcessError::Exhausted)?;
    let mut effects = WakeEffects::default();
    let wake = zone.wake_placed(
        &guard,
        channel.mm,
        address,
        u32::MAX,
        u32::MAX,
        Waker::El1 { slot },
        &mut [],
        &mut effects,
    );
    drop(guard);
    if matches!(wake, Err(carrick_sched_core::WakeRefusal::Unplaceable)) {
        return service.wake_unplaceable_wait(ProcessWaitChannel {
            mm: carrick_el1_abi::EntryMmKey::from_raw(channel.mm),
            address: core::num::NonZeroU64::new(address).ok_or(NativeProcessError::Quarantined)?,
        });
    }
    wake.map_err(|_| NativeProcessError::Quarantined)?;
    service.wake_effects(effects);
    Ok(())
}

fn owned_control<'a>(
    page: &'a ThreadLifecyclePage,
    leader: &'a ThreadControlSlot,
    address: u64,
) -> Option<&'a ThreadControlSlot> {
    if leader as *const _ as u64 == address {
        return Some(leader);
    }
    for index in 0..page.entry_count() {
        let (generation, state) = page.state(index)?;
        if !matches!(
            state,
            carrick_el1_abi::EntryState::Born | carrick_el1_abi::EntryState::Published
        ) {
            continue;
        }
        let entry = EntryRef::new(index as u32, generation);
        if page.control_address(entry) == Some(address) {
            // SAFETY: the retained lifecycle owner licenses this address for
            // this live entry. Stock is not reclaimed while the entry is live.
            let control = unsafe { &*(address as *const ThreadControlSlot) };
            return (control.entry() == Some(entry)).then_some(control);
        }
    }
    None
}

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
    ForkRefused(super::native_fork_refusal::NativeForkRefusal),
    Unsupported,
    GroupExitCustody,
    Busy,
    Quarantined,
    NoChild,
}
impl NativeProcessError {
    pub fn run_failure_reason(self) -> carrick_core_abi::NativeRunFailureReason {
        use carrick_core_abi::NativeRunFailureReason as R;
        match self {
            Self::Invalid => R::NativeInvalid,
            Self::Stale => R::NativeStale,
            Self::Exhausted => R::NativeExhausted,
            Self::Fault => R::NativeFault,
            Self::ForkRefused(refusal) => refusal.error().run_failure_reason(),
            Self::Unsupported => R::NativeUnsupported,
            Self::Busy => R::NativeBusy,
            Self::Quarantined => R::NativeQuarantined,
            Self::NoChild => R::NativeNoChild,
            Self::GroupExitCustody => R::X86GroupExitCustody,
        }
    }
    pub fn errno(self) -> i64 {
        match self {
            Self::Invalid | Self::Stale => -22,
            Self::Exhausted | Self::Busy => -11,
            Self::Fault => -14,
            Self::ForkRefused(refusal) => refusal.error().errno(),
            Self::Unsupported | Self::GroupExitCustody => -38,
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
    fn fork_child_context(&self, parent: C, prepared: &Self::PreparedMm) -> C {
        parent.fork_child(self.prepared_context(prepared))
    }
    fn fork_child_context_boxed(&self, parent: C, prepared: &Self::PreparedMm) -> Box<C> {
        Box::new(self.fork_child_context(parent, prepared))
    }
    fn child_lifecycle(&self, prepared: &Self::PreparedMm) -> NativeLifecycleResources<'a>;
    fn commit_mm(
        &mut self,
        prepared: Self::PreparedMm,
    ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)>;
    fn commit_child(
        &mut self,
        prepared: Self::PreparedMm,
        child_task: core::num::NonZeroU64,
        child_execution: core::num::NonZeroU64,
    ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
        let _ = (child_task, child_execution);
        self.commit_mm(prepared)
    }
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
    /// A guest drain opened ingress capacity for an owned host admission.
    fn request_ingress_producer_boundary(&mut self);
    fn wake_unplaceable_wait(
        &mut self,
        _channel: ProcessWaitChannel,
    ) -> Result<(), NativeProcessError> {
        Err(NativeProcessError::Quarantined)
    }
    /// Plain fork copies descriptors into a graph-issued table identity.
    fn child_file_table(&self, _parent_table: u64, issued: u64) -> u64 {
        issued
    }
    fn fork_fd_table(
        &mut self,
        _parent_table: u64,
        _child_table: u64,
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }
    fn retire_fd_table(&mut self, _table: u64) {}
    /// The root exit crossing terminates every remaining thread of the run,
    /// so a root `exit_group` may complete while siblings are still live.
    /// Their census and pool entries stay with the host, which retires them
    /// at run teardown; this owner cancels only the records it executes.
    fn root_exit_ends_run(&self) -> bool {
        false
    }
    fn signal_deadline(
        &mut self,
        nanos: u64,
    ) -> Result<carrick_guest_arch::Deadline, NativeProcessError> {
        #[cfg(not(target_os = "none"))]
        {
            let _ = nanos;
            Err(NativeProcessError::Unsupported)
        }
        #[cfg(target_os = "none")]
        {
            let mut backend = crate::isa::signal_clock();
            use carrick_guest_arch::InterruptBackend;
            let now = backend
                .counter()
                .map_err(|_| NativeProcessError::Unsupported)?
                .raw();
            let frequency = backend
                .frequency()
                .map_err(|_| NativeProcessError::Unsupported)?
                .raw()
                .get();
            let ticks = (u128::from(nanos) * u128::from(frequency)).div_ceil(1_000_000_000);
            let ticks = u64::try_from(ticks).map_err(|_| NativeProcessError::Invalid)?;
            Ok(carrick_guest_arch::Deadline(
                carrick_guest_arch::CounterTick::new(now.saturating_add(ticks)),
            ))
        }
    }
    fn arm_signal_timer(
        &mut self,
        deadline: carrick_guest_arch::Deadline,
    ) -> Result<(), NativeProcessError> {
        #[cfg(not(target_os = "none"))]
        {
            let _ = deadline;
            Err(NativeProcessError::Unsupported)
        }
        #[cfg(target_os = "none")]
        {
            use carrick_guest_arch::InterruptBackend;
            crate::isa::signal_clock()
                .arm_timer(Some(deadline))
                .map_err(|_| NativeProcessError::Unsupported)
        }
    }
    fn signal_now(&mut self) -> Result<carrick_guest_arch::CounterTick, NativeProcessError> {
        #[cfg(not(target_os = "none"))]
        {
            Err(NativeProcessError::Unsupported)
        }
        #[cfg(target_os = "none")]
        {
            use carrick_guest_arch::InterruptBackend;
            crate::isa::signal_clock()
                .counter()
                .map_err(|_| NativeProcessError::Unsupported)
        }
    }
    fn copy_signal_bytes(
        &mut self,
        _mm: &Self::Mm,
        _address: UserVa,
        _bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        Err(NativeProcessError::Unsupported)
    }
    fn copy_siginfo(
        &mut self,
        _mm: &Self::Mm,
        _address: UserVa,
        _info: &carrick_syscall_abi::LinuxSiginfo,
    ) -> Result<(), NativeProcessError> {
        Err(NativeProcessError::Unsupported)
    }
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
/// Exact in-zone key retained by the parent wait owner through terminal wake.
#[derive(Clone, Copy)]
pub struct ProcessWaitChannel {
    pub mm: carrick_el1_abi::EntryMmKey,
    pub address: core::num::NonZeroU64,
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
/// An unadopted lifecycle member has real guest record custody but no issued
/// executor generation. Never manufacture a TaskSerial to index that member.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum NativeThreadIdentity {
    Issued(TaskKey),
    Born(TaskId),
}
impl NativeThreadIdentity {
    fn from_binding(binding: ExecutionBinding) -> Result<Self, NativeProcessError> {
        let id = carrick_personality_linux::identity::task_id_from_linux_pid(
            i32::try_from(binding.task.raw()).map_err(|_| NativeProcessError::Invalid)?,
        )
        .map_err(|_| NativeProcessError::Invalid)?;
        Ok(match TaskSerial::from_raw_u64(binding.generation.raw()) {
            Some(serial) => Self::Issued(TaskKey { id, serial }),
            None => Self::Born(id),
        })
    }
    fn id(self) -> TaskId {
        match self {
            Self::Issued(key) => key.id,
            Self::Born(id) => id,
        }
    }
    fn issued(self) -> Option<TaskKey> {
        match self {
            Self::Issued(key) => Some(key),
            Self::Born(_) => None,
        }
    }
}

#[derive(::core::clone::Clone)]
pub struct NativeMember<'a, C: ProcessContext> {
    thread: NativeThreadIdentity,
    process: TaskKey,
    zone: &'a ZoneTables<C>,
    record: RecordRef,
    control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
    expected_host: carrick_core::terminal::HostThreadRetirementReceipt,
}
impl<C: ProcessContext> ExitMember for NativeMember<'_, C> {
    fn exit_task(&self) -> TaskKey {
        self.process
    }
}
fn retain_member_control(
    control: &ThreadControlSlot,
) -> Result<
    Arc<carrick_core::lifecycle::MemberControlCustody<'_, ThreadControlSlot>>,
    NativeProcessError,
> {
    carrick_core::lifecycle::MemberControlCustody::retain(control)
        .map(Arc::new)
        .map_err(|_| NativeProcessError::Stale)
}
fn pool_host_identity(
    page: &ThreadLifecyclePage,
    entry: EntryRef,
) -> Result<carrick_core::terminal::HostThreadRetirementReceipt, NativeProcessError> {
    let identity = page.identity(entry).ok_or(NativeProcessError::Stale)?;
    carrick_core::terminal::HostThreadRetirementReceipt::from_parts(
        carrick_core_abi::EntryTaskKey::from_raw(u64::from(identity.tid)),
        identity.execution,
        carrick_core_abi::EntryThreadGeneration::from_raw(identity.thread_serial),
    )
    .ok_or(NativeProcessError::Stale)
}

fn member_host_identity(
    page: &ThreadLifecyclePage,
    control: &ThreadControlSlot,
    binding: ExecutionBinding,
) -> Result<carrick_core::terminal::HostThreadRetirementReceipt, NativeProcessError> {
    if let Some(entry) = control.entry() {
        // The pool owns the host process incarnation throughout adoption.
        // A zone binding's generation versions its CPU snapshot; substituting
        // it makes a genuine host retirement receipt impossible to satisfy.
        pool_host_identity(page, entry)
    } else {
        Ok(carrick_core::terminal::HostThreadRetirementReceipt::from_binding(binding))
    }
}

pub struct NativeResources<'a, M, C: ProcessContext> {
    _control_custody: carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>,
    zone: &'a ZoneTables<C>,
    record: RecordRef,
    control: &'a ThreadControlSlot,
    page: &'a ThreadLifecyclePage,
    members: Vec<NativeMember<'a, C>>,
    mm: M,
    address: AddressContext<RootGpa>,
    /// Consumed on the child's first return to user mode, after its MM split.
    pending_child_tid: Option<UserVa>,
    signals: NativeProcessSignals<carrick_personality_linux::abi::signal::LinuxSiginfo>,
    _thread_claim: NativeClaim,
    channel: Option<Arc<WaitChannel>>,
    usage: TaskRusage,
    file_table: u64,
}
pub type NativeForkPreparation<'a, M, P, C> = PreparedFork<
    VisibleNamespace,
    carrick_personality_linux::identity::TaskUid,
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
    type SignalTarget = NativeExitSignals<
        carrick_personality_linux::abi::signal::LinuxSiginfo,
        &'a ThreadControlSlot,
    >;
    fn wait_event(&self, _: WaitJobControl, _: bool) -> Option<()> {
        None
    }
    fn own_members_and_resources(&self) -> (Vec<Self::Member>, M) {
        (self.members.clone(), self.mm.clone())
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
    GuestTask<VisibleNamespace, carrick_personality_linux::identity::TaskUid, Custody<'a, M, C>>;
type Owner<'a, M, C> = GuestProcessOwner<
    VisibleNamespace,
    carrick_personality_linux::identity::TaskUid,
    Custody<'a, M, C>,
>;

#[cfg(test)]
#[test]
fn arm_process_registry_moves_bounded_handles() {
    type Native = Custody<'static, AddressContext<RootGpa>, carrick_el1_abi::Aarch64ParkedContext>;
    // Registry insertion/removal must not copy an ISA save area on the EL1
    // stack. The retirement row retains the same owned execution custody.
    type Task =
        NativeIdentityTask<'static, AddressContext<RootGpa>, carrick_el1_abi::Aarch64ParkedContext>;
    assert!(core::mem::size_of::<Task>() <= 64);
    assert!(core::mem::size_of::<super::process_owner::GuestRetiring<Native>>() <= 128);
}
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
enum OutstandingExitReceipt<'a> {
    Pool {
        entry: carrick_el1_abi::EntryRef,
        control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
        expected_host: carrick_core::terminal::HostThreadRetirementReceipt,
    },
    Adopted {
        binding: ExecutionBinding,
        control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
    },
    HostBorn {
        identity: carrick_core::terminal::HostThreadRetirementReceipt,
        index: usize,
    },
}

struct PendingExit<'a> {
    status: LinuxWaitStatus,
    entry: OwnerEntry,
    caller: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
    channel: Arc<WaitChannel>,
    wake: Option<ExitWakeCustody>,
    outstanding: Vec<OutstandingExitReceipt<'a>>,
    members: carrick_core::terminal::MemberSet,
    custody: Option<
        carrick_core::terminal::TerminalCustody<
            carrick_core::terminal::Process,
            carrick_core::terminal::Closing,
        >,
    >,
}

// Pool entries and the carrier's bounded record registry are the maximum
// member population. A concurrent retirement may lower live() after the
// snapshot without reducing the receipts Closing still owes.
const MEMBER_SET_CAPACITY: usize =
    carrick_el1_abi::THREAD_POOL_ENTRIES + carrick_sched_core::ZONE_RECORDS;

impl PendingExit<'_> {
    fn completed_receipts(
        &self,
        page: &ThreadLifecyclePage,
    ) -> Option<carrick_core::terminal::CompletedMemberReceipts> {
        let mut pool = Vec::new();
        let mut host = Vec::new();
        for receipt in &self.outstanding {
            match receipt {
                OutstandingExitReceipt::Pool {
                    entry,
                    control,
                    expected_host,
                } => pool.push(carrick_core::terminal::PoolMemberObservation {
                    entry: *entry,
                    member: control.control(),
                    expected_host: *expected_host,
                }),
                OutstandingExitReceipt::Adopted { binding, control } => {
                    host.push(carrick_core::terminal::HostMemberObservation::Adopted {
                        binding: carrick_core::terminal::HostThreadRetirementReceipt::from_binding(
                            *binding,
                        ),
                        member: control.control(),
                    });
                }
                OutstandingExitReceipt::HostBorn { identity, index } => {
                    host.push(carrick_core::terminal::HostMemberObservation::HostBorn {
                        identity: *identity,
                        index: *index,
                    });
                }
            }
        }
        self.custody
            .as_ref()?
            .observe_members(page, &self.members, &pool, &host)
    }
}

#[derive(::core::clone::Clone)]
enum PendingIpcPayload {
    Msgsnd {
        msqid: i32,
        mtype: i64,
        data: Vec<u8>,
        msgflg: i32,
    },
    Msgrcv {
        msqid: i32,
        msgp: UserVa,
        msgsz: usize,
        msgtyp: i64,
        msgflg: i32,
    },
    Semop {
        semid: i32,
        ops: Vec<(u16, i16, i16)>,
        timeout_deadline: Option<carrick_guest_arch::Deadline>,
        blocking_sem: Option<(u16, bool)>,
    },
}

#[allow(dead_code)]
struct PendingIpc {
    caller: TaskKey,
    channel: Arc<WaitChannel>,
    precheck_gen: TaskWakeGeneration,
    payload: PendingIpcPayload,
}

enum ContinuationPark {
    Parked,
    Rescan,
    Interrupted,
}

enum PendingContinuation {
    Wait(PendingWait),
    Ipc(PendingIpc),
}

type IpcWaitChannels = Arc<SpinLock<Vec<(u64, Arc<WaitChannel>)>>>;

#[derive(Clone, Copy)]
enum PendingSignalKind {
    Suspend,
    Wait {
        set: carrick_signal_core::SignalSet,
        info: UserVa,
    },
}
struct PendingSignalWait {
    kind: PendingSignalKind,
    channel: Arc<WaitChannel>,
    deadline: Option<carrick_guest_arch::Deadline>,
}
struct Graph<'a, M: Clone, C: ProcessContext> {
    owner: Owner<'a, M, C>,
    root_key: TaskKey,
    namespace: Arc<SpinLock<NamespaceState>>,
    visible_namespace: VisibleNamespace,
    serials: SerialAllocator,
    pending: BTreeMap<TaskKey, PendingContinuation>,
    pending_exit: BTreeMap<TaskKey, PendingExit<'a>>,
    signal_waits: BTreeMap<RecordRef, PendingSignalWait>,
    suspend_masks: BTreeMap<RecordRef, carrick_signal_core::policy::SigBlockMask>,
    _root_roles: NativeClaim,
    uts: carrick_personality_linux::sysinfo::LinuxUtsname,
    ipc: Arc<SpinLock<IpcNamespace>>,
}
impl<'a, M: Clone, C: ProcessContext> Drop for Graph<'a, M, C> {
    fn drop(&mut self) {
        NATIVE_SUSPEND_MASKS.fetch_sub(self.suspend_masks.len(), Ordering::Release);
    }
}
pub struct NativeProcessRuntime<'a, M: Clone, C: ProcessContext> {
    graph: SpinLock<Graph<'a, M, C>>,
    zone: &'a ZoneTables<C>,
    ipc_channels: IpcWaitChannels,
    #[cfg(test)]
    signal_check_hook: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    closing_race_hook: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    pool_control_hook: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    pool_retained_hook: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    settle_race_hook: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    raw_exit_after_commit_hook: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    registry: SpinLock<Option<&'a NativeProcessRegistry<'a, M, C>>>,
}

/// An exact execution incarnation within one carrier. A task or MM number
/// alone never selects a process owner across independent roots.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::Eq,
    ::core::cmp::Ord,
    ::core::cmp::PartialEq,
    ::core::cmp::PartialOrd,
)]
struct NativeExecutionKey {
    carrier: usize,
    task: NativeThreadIdentity,
    mm: u64,
    thread_generation: u64,
    root: u64,
    address_generation: u64,
}

impl NativeExecutionKey {
    fn binding(self) -> ExecutionBinding {
        use carrick_core_abi::entry::{
            EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
        };
        ExecutionBinding {
            task: EntryTaskKey::from_raw(self.task.id().raw() as u64),
            generation: EntryGeneration::from_raw(
                self.task.issued().map_or(0, |key| key.serial.raw()),
            ),
            mm: EntryMmKey::from_raw(self.mm),
            thread_generation: EntryThreadGeneration::from_raw(self.thread_generation),
        }
    }

    fn new<C: ProcessContext>(
        zone: &ZoneTables<C>,
        binding: ExecutionBinding,
        address: AddressContext<RootGpa>,
    ) -> Result<Self, NativeProcessError> {
        let task = NativeThreadIdentity::from_binding(binding)?;
        if binding.mm.raw() != address.mm.raw().get() {
            return Err(NativeProcessError::Stale);
        }
        Ok(Self {
            carrier: core::ptr::from_ref(zone).addr(),
            task,
            mm: address.mm.raw().get(),
            thread_generation: binding.thread_generation.raw(),
            root: address.root.address().raw(),
            address_generation: address.generation.raw().get(),
        })
    }
}

type NativeRecordKey = (usize, u32, u64);
type NativeGroupKey = (usize, u64, u64, usize, u32);

struct NativeChildRegistration {
    parent_binding: ExecutionBinding,
    parent_address: AddressContext<RootGpa>,
    child: TaskKey,
    thread_generation: u64,
    address: AddressContext<RootGpa>,
    record: RecordRef,
}

struct NativeOwnerMember<'a, M: Clone, C: ProcessContext> {
    runtime: Arc<NativeProcessRuntime<'a, M, C>>,
    process: TaskKey,
    address: AddressContext<RootGpa>,
    record: RecordRef,
    control: Arc<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
}

impl<'a, M: Clone, C: ProcessContext> Clone for NativeOwnerMember<'a, M, C> {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            process: self.process,
            address: self.address,
            record: self.record,
            control: self.control.clone(),
        }
    }
}

struct NativeRegistryState<'a, M: Clone, C: ProcessContext> {
    members: BTreeMap<NativeExecutionKey, NativeOwnerMember<'a, M, C>>,
    groups: BTreeMap<NativeGroupKey, (Arc<NativeProcessRuntime<'a, M, C>>, TaskKey)>,
    records: BTreeMap<NativeRecordKey, NativeExecutionKey>,
    by_process: BTreeMap<(usize, TaskKey), (NativeGroupKey, Vec<NativeExecutionKey>)>,
}

/// Shared owner registry. Each admitted root owns an independent process
/// graph; children retain their parent's graph through exact member indices.
pub struct NativeProcessRegistry<'a, M: Clone, C: ProcessContext> {
    state: SpinLock<NativeRegistryState<'a, M, C>>,
}

impl<'a, M: Clone, C: ProcessContext> NativeProcessRegistry<'a, M, C> {
    /// Consume host retirement receipts when a sibling next enters the ring.
    /// HostRetiring records the exit path before the shared entry is reaped;
    /// the exact receipt arrives only after kernel and runtime withdrawal.
    fn fold_host_receipts(&self, runtime: &Arc<NativeProcessRuntime<'a, M, C>>, process: TaskKey) {
        let carrier = core::ptr::from_ref(runtime.zone).addr();
        let mut state = self.state.lock();
        let Some((_, keys)) = state.by_process.get(&(carrier, process)) else {
            return;
        };
        let completed: Vec<_> = keys
            .iter()
            .filter_map(|key| {
                let member = state.members.get(key)?;
                member
                    .control
                    .host_retirement()
                    .is_some_and(|receipt| receipt.matches(key.binding()))
                    .then_some((*key, member.record, member.control.visible_tid()))
            })
            .collect();
        if completed.is_empty() {
            return;
        }
        let mut graph = runtime.graph.lock();
        if let Ok(row) = graph.owner.task_mut(process) {
            for (key, record, visible_tid) in &completed {
                if let Some(tid) = visible_tid {
                    row.remove_thread(*tid);
                    if let Ok(tid) = i32::try_from(*tid) {
                        carrick_signal_core::wait::clear_non_interrupting_for(tid);
                    }
                }
                carrick_signal_core::wait::clear_non_interrupting_for(key.task.id().raw());
                row.native_mut().resources_mut().members.retain(|member| {
                    member.record != *record && member.thread.id() != key.task.id()
                });
            }
        }
        drop(graph);
        for (key, record, _) in completed {
            state.members.remove(&key);
            state
                .records
                .remove(&Self::record_key(runtime.zone, record));
            if let Some((_, keys)) = state.by_process.get_mut(&(carrier, process)) {
                keys.retain(|candidate| *candidate != key);
            }
        }
    }

    fn cancel_members(
        &self,
        runtime: &NativeProcessRuntime<'a, M, C>,
        page: &ThreadLifecyclePage,
        members: &carrick_core::terminal::MemberSet,
        adopted: &[(ExecutionBinding, &'a ThreadControlSlot, RecordRef)],
    ) {
        let wait = NativeBucketWait {
            lifetime: core::marker::PhantomData,
            #[cfg(test)]
            probe: None,
        };
        for identity in members.host() {
            if let Some((_, control, record)) = adopted.iter().find(|(binding, _, _)| {
                *identity
                    == carrick_core::terminal::HostThreadRetirementReceipt::from_binding(*binding)
            }) {
                if control.host_retirement().is_some()
                    || control.entry().is_some_and(|entry| {
                        carrick_el1_abi::Lifecycle::expected_exit_receipt(
                            page,
                            *control,
                            Some(entry),
                        ) == carrick_core::lifecycle::ExpectedExitReceipt::AlreadyExited
                    })
                {
                    continue;
                }
                if runtime.zone.live(*record).is_some() {
                    let _ = runtime
                        .zone
                        .claim_for_host(*record, None, Handback::Cancelled, &wait);
                }
            } else if let Some(index) = (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
                .find(|&index| page.host_birth_identity(index) == Some(*identity))
            {
                page.request_host_birth_cancel(index);
            }
        }
        for entry in members.pool() {
            let Some(address) = page.control_address(*entry) else {
                continue;
            };
            // SAFETY: a live page entry pins its control allocation through
            // terminal settlement; the entry generation authenticates reuse.
            let control = unsafe { &*(address as *const ThreadControlSlot) };
            if control.host_retirement().is_some()
                || carrick_el1_abi::Lifecycle::expected_exit_receipt(page, control, Some(*entry))
                    == carrick_core::lifecycle::ExpectedExitReceipt::AlreadyExited
            {
                continue;
            }
            let Some(record) = control.zone_record() else {
                continue;
            };
            let Some(owned) = runtime.zone.live(record) else {
                continue;
            };
            let Some(identity) = page.identity(*entry) else {
                continue;
            };
            if owned.identity().tid != u64::from(identity.tid)
                || owned.identity().serial != identity.thread_serial
            {
                continue;
            }
            let _ = runtime
                .zone
                .claim_for_host(record, None, Handback::Cancelled, &wait);
        }
    }

    fn adopted_members(
        state: &NativeRegistryState<'a, M, C>,
        runtime: &NativeProcessRuntime<'a, M, C>,
        process: TaskKey,
        caller: ExecutionBinding,
        page: &ThreadLifecyclePage,
    ) -> Vec<(ExecutionBinding, &'a ThreadControlSlot, RecordRef)> {
        let carrier = core::ptr::from_ref(runtime.zone).addr();
        state
            .by_process
            .get(&(carrier, process))
            .map_or_else(Vec::new, |(_, keys)| {
                keys.iter()
                    .filter_map(|key| {
                        let binding = key.binding();
                        (binding != caller && binding.issued())
                            .then(|| {
                                state
                                    .members
                                    .get(key)
                                    // Core gives each exact identity one
                                    // receipt kind. In-zone completion owes
                                    // neither a pool nor a host receipt.
                                    .and_then(|member| {
                                        (member.control.entry().is_none()
                                            && carrick_el1_abi::Lifecycle::expected_exit_receipt(
                                            page,
                                            member.control.control(),
                                            member.control.entry(),
                                        ) == carrick_core::lifecycle::ExpectedExitReceipt::Host)
                                            .then_some((binding, member.control.control(), member.record))
                                    })
                            })
                            .flatten()
                    })
                    .collect()
            })
    }

    pub const fn new() -> Self {
        Self {
            state: SpinLock::new(NativeRegistryState {
                members: BTreeMap::new(),
                groups: BTreeMap::new(),
                records: BTreeMap::new(),
                by_process: BTreeMap::new(),
            }),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.state.lock().members.is_empty()
    }

    fn record_key(zone: &ZoneTables<C>, record: RecordRef) -> NativeRecordKey {
        (
            core::ptr::from_ref(zone).addr(),
            record.id.raw(),
            record.incarnation,
        )
    }

    fn group_key(
        zone: &ZoneTables<C>,
        address: AddressContext<RootGpa>,
        page: &ThreadLifecyclePage,
        visible_pid: u32,
    ) -> NativeGroupKey {
        (
            core::ptr::from_ref(zone).addr(),
            address.mm.raw().get(),
            address.root.address().raw(),
            core::ptr::from_ref(page).addr(),
            visible_pid,
        )
    }

    pub fn register_root(
        &'a self,
        runtime: Arc<NativeProcessRuntime<'a, M, C>>,
        source: BornInZoneSource<'a, C>,
        current: &CurrentTask,
        address: AddressContext<RootGpa>,
    ) -> Result<(), NativeProcessError> {
        if !core::ptr::eq(runtime.zone, source.zone) {
            return Err(NativeProcessError::Stale);
        }
        let binding = super::common_entry::execution_binding(current);
        let key = NativeExecutionKey::new(source.zone, binding, address)?;
        let process = key.task.issued().ok_or(NativeProcessError::Invalid)?;
        let owned = runtime
            .task_binding(process)
            .ok_or(NativeProcessError::Stale)?;
        if owned.address != address {
            return Err(NativeProcessError::Stale);
        }
        let (page, visible_pid, control) = {
            let graph = runtime.graph.lock();
            let row = graph
                .owner
                .task(process)
                .map_err(|_| NativeProcessError::Stale)?;
            (
                row.native().resources().page,
                row.metadata().namespace_pid,
                row.native().resources().control,
            )
        };
        let mut state = self.state.lock();
        let record_key = Self::record_key(source.zone, owned.record);
        let group_key = Self::group_key(source.zone, address, page, visible_pid);
        if state.members.contains_key(&key)
            || state.records.contains_key(&record_key)
            || state.groups.contains_key(&group_key)
        {
            return Err(NativeProcessError::Busy);
        }
        state.members.insert(
            key,
            NativeOwnerMember {
                runtime: runtime.clone(),
                process,
                address,
                record: owned.record,
                control: retain_member_control(control)?,
            },
        );
        state.groups.insert(group_key, (runtime.clone(), process));
        state
            .by_process
            .insert((key.carrier, process), (group_key, vec![key]));
        state.records.insert(record_key, key);
        *runtime.registry.lock() = Some(self);
        state
            .members
            .get(&key)
            .ok_or(NativeProcessError::Stale)?
            .control
            .commit_native_signal_owner();
        Ok(())
    }

    /// Renew retained execution custody (including Born -> issued adoption).
    /// The process key and address incarnation remain owned by the same graph.
    #[inline(never)]
    pub fn rehome_entry(
        &self,
        source: BornInZoneSource<'a, C>,
        current: &CurrentTask,
        address: AddressContext<RootGpa>,
        page: &ThreadLifecyclePage,
        control: &ThreadControlSlot,
    ) -> Result<Option<Arc<NativeProcessRuntime<'a, M, C>>>, NativeProcessError> {
        let binding = super::common_entry::execution_binding(current);
        let host_identity = member_host_identity(page, control, binding)?;
        let key = NativeExecutionKey::new(source.zone, binding, address)?;
        let pid = current.visible_pid().ok_or(NativeProcessError::Stale)?;
        let record = source
            .zone
            .slot(source.slot)
            .current()
            .or_else(|| source.zone.slot(source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        carrick_core::entry::prepare_handoff(binding, source, record)
            .ok_or(NativeProcessError::Stale)?;
        let reference = source.zone.record_ref(record);
        let mut state = self.state.lock();
        let (runtime, process) = state
            .groups
            .get(&Self::group_key(source.zone, address, page, pid))
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        let mut graph = runtime.graph.lock();
        let resources = graph
            .owner
            .task_mut(process)
            .map_err(|_| NativeProcessError::Stale)?
            .native_mut()
            .resources_mut();
        if !core::ptr::eq(resources.page, page)
            || resources.address != address
            || (control.entry().is_none()
                && core::ptr::eq(resources.control, control) != (process.id == key.task.id()))
            || current.metadata.lifecycle_page.load(Ordering::Acquire) != page as *const _ as u64
            || current.metadata.control_slot.load(Ordering::Acquire) != control as *const _ as u64
        {
            return Err(NativeProcessError::Stale);
        }
        let Some(member_index) = resources
            .members
            .iter()
            .position(|member| core::ptr::eq(member.control.control(), control))
        else {
            return Ok(None);
        };
        if resources.members[member_index].thread.id() != key.task.id() {
            return Err(NativeProcessError::Stale);
        }
        let old_record = resources.members[member_index].record;
        let (_, keys) = state
            .by_process
            .get(&(key.carrier, process))
            .ok_or(NativeProcessError::Stale)?;
        let key_index = keys.iter().position(|candidate| {
            state
                .members
                .get(candidate)
                .is_some_and(|member| member.record == old_record)
        });
        let Some(key_index) = key_index else {
            return Ok(None);
        };
        let old_key = keys[key_index];
        if old_key.thread_generation != key.thread_generation {
            return Err(NativeProcessError::Stale);
        }
        if old_record != reference && signal_record_exists(source.zone, old_record) {
            return Err(NativeProcessError::Busy);
        }
        let record_key = Self::record_key(source.zone, reference);
        if (old_key != key && state.members.contains_key(&key))
            || (old_record != reference && state.records.contains_key(&record_key))
        {
            return Err(NativeProcessError::Busy);
        }
        let mut member = state
            .members
            .get(&old_key)
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        member.record = reference;
        // Every refusing check precedes publication under both owner guards.
        if let Some(pending) = graph.pending_exit.get_mut(&process) {
            let old_binding = old_key.binding();
            if pending.outstanding.iter().any(|receipt| {
                matches!(receipt, OutstandingExitReceipt::Adopted { binding, control: expected }
                    if *binding == old_binding && core::ptr::eq(expected.control(), control))
            }) && !pending.members.rehome_host(
                carrick_core::terminal::HostThreadRetirementReceipt::from_binding(old_binding),
                carrick_core::terminal::HostThreadRetirementReceipt::from_binding(key.binding()),
            ) {
                return Err(NativeProcessError::Stale);
            }
            for receipt in &mut pending.outstanding {
                if let OutstandingExitReceipt::Pool {
                    control: expected,
                    expected_host,
                    ..
                } = receipt
                    && core::ptr::eq(expected.control(), control)
                {
                    *expected_host = host_identity;
                }
                if let OutstandingExitReceipt::Adopted {
                    binding,
                    control: expected,
                } = receipt
                    && *binding == old_binding
                    && core::ptr::eq(expected.control(), control)
                {
                    *binding = key.binding();
                }
            }
        }
        state
            .by_process
            .get_mut(&(key.carrier, process))
            .ok_or(NativeProcessError::Stale)?
            .1[key_index] = key;
        let resources = graph
            .owner
            .task_mut(process)
            .map_err(|_| NativeProcessError::Stale)?
            .native_mut()
            .resources_mut();
        if core::ptr::eq(resources.control, control) {
            resources.record = reference;
        }
        resources.members[member_index].record = reference;
        resources.members[member_index].thread = key.task;
        resources.members[member_index].expected_host = host_identity;
        state.members.remove(&old_key);
        state
            .records
            .remove(&Self::record_key(source.zone, old_record));
        state.members.insert(key, member);
        state.records.insert(record_key, key);
        drop(graph);
        Ok(Some(runtime))
    }

    pub fn for_entry(
        &self,
        source: BornInZoneSource<'_, C>,
        current: &CurrentTask,
        address: AddressContext<RootGpa>,
    ) -> Result<Arc<NativeProcessRuntime<'a, M, C>>, NativeProcessError> {
        let binding = super::common_entry::execution_binding(current);
        let key = NativeExecutionKey::new(source.zone, binding, address)?;
        let (runtime, process) = self
            .state
            .lock()
            .members
            .get(&key)
            .map(|member| (member.runtime.clone(), member.process))
            .ok_or(NativeProcessError::Stale)?;
        self.fold_host_receipts(&runtime, process);
        Ok(runtime)
    }

    pub fn for_record(
        &self,
        zone: &ZoneTables<C>,
        record: RecordRef,
    ) -> Option<Arc<NativeProcessRuntime<'a, M, C>>> {
        let state = self.state.lock();
        let key = state.records.get(&Self::record_key(zone, record))?;
        state.members.get(key).map(|member| member.runtime.clone())
    }

    /// Cheap read-only signal checkpoint predicate before an ARM hardware
    /// context is saved. The record index and process graph remain the same
    /// authority used by the delivery owner; a stale record is never treated
    /// as an empty signal set.
    pub fn signal_checkpoint_needed(&self, zone: &ZoneTables<C>, record: RecordRef) -> bool {
        if NATIVE_SUSPEND_MASKS.load(Ordering::Acquire) == 0 && signal_record_exists(zone, record) {
            let control_address = zone.record(record.id).identity().control_slot;
            if control_address != 0 {
                // SAFETY: an authenticated live or host-owned zone record
                // retains its published control slot in lifecycle custody.
                let control = unsafe { &*(control_address as *const ThreadControlSlot) };
                if control.native_signal_owner()
                    && control.zone_record() == Some(record)
                    && !control.forwarded_wait_mask_armed()
                {
                    let pending = super::native_process_signals::pending_summary_word();
                    let blocked = control.blocked().0;
                    let forced = carrick_signal_core::policy::Signal::SEGV.bit()
                        | carrick_signal_core::policy::Signal::KILL.bit();
                    if pending & (!blocked | forced) == 0 {
                        return false;
                    }
                }
            }
        }
        let state = self.state.lock();
        let Some(key) = state.records.get(&Self::record_key(zone, record)) else {
            return true;
        };
        let Some(member) = state.members.get(key) else {
            return true;
        };
        let graph = member.runtime.graph.lock();
        let Ok(row) = graph.owner.task(member.process) else {
            return true;
        };
        if graph.suspend_masks.contains_key(&record) || member.control.forwarded_wait_mask_armed() {
            return true;
        }
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(member.control.blocked().0),
        );
        row.native()
            .resources()
            .signals()
            .has_deliverable(record, blocked)
    }

    fn external_member<'s>(
        state: &'s NativeRegistryState<'a, M, C>,
        zone: &ZoneTables<C>,
        event: carrick_el1_abi::ExternalSignalRecord,
    ) -> Option<&'s NativeOwnerMember<'a, M, C>> {
        let key = state.records.get(&Self::record_key(zone, event.record()))?;
        let member = state.members.get(key)?;
        let binding = key.binding();
        (event.matches_live(
            carrick_core_abi::EntryEventIdentity::from_binding(binding),
            binding,
            member.record,
        ) && signal_record_exists(zone, member.record))
        .then_some(member)
    }

    fn external_event_member<'s>(
        state: &'s NativeRegistryState<'a, M, C>,
        zone: &ZoneTables<C>,
        event: carrick_el1_abi::ExternalSignalRecord,
    ) -> Option<&'s NativeOwnerMember<'a, M, C>> {
        if event.scope() == carrick_el1_abi::ExternalSignalScope::Thread {
            return Self::external_member(state, zone, event);
        }
        // A process-directed event may outlive the polling thread or an
        // execve MM replacement. Authenticate the durable process generation,
        // then choose a surviving member of that exact process. When the
        // observing thread is still a live member of this process and does
        // not block the signal, honour its wait-interruption claim first.
        if !event.identity().issued()
            || !event.identity().matches(event.binding())
            || event.binding().generation != event.process_generation()
        {
            return None;
        }
        if let Some(member) = Self::external_member(state, zone, event)
            && member.process.id.raw() as u64 == event.process_id().raw()
            && member.process.serial.raw() == event.process_generation().raw()
        {
            let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(member.control.blocked().0),
            );
            if !blocked.contains(event.signal()) {
                return Some(member);
            }
        }
        let carrier = core::ptr::from_ref(zone).addr();
        let (_, keys) = state
            .by_process
            .iter()
            .find_map(|((place, process), group)| {
                (*place == carrier
                    && process.id.raw() as u64 == event.process_id().raw()
                    && process.serial.raw() == event.process_generation().raw())
                .then_some(group)
            })?;
        let mut fallback = None;
        for key in keys {
            let Some(member) = state.members.get(key) else {
                continue;
            };
            fallback.get_or_insert(member);
            let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(member.control.blocked().0),
            );
            if !blocked.contains(event.signal()) {
                return Some(member);
            }
        }
        fallback
    }

    /// Resolve one ingress event through the exact live member index. A tid,
    /// MM, or record slot on its own is never authority to admit a signal.
    pub fn for_external_event(
        &self,
        zone: &ZoneTables<C>,
        event: carrick_el1_abi::ExternalSignalRecord,
    ) -> Option<Arc<NativeProcessRuntime<'a, M, C>>> {
        let state = self.state.lock();
        let member = Self::external_event_member(&state, zone, event)?;
        let graph = member.runtime.graph.lock();
        let row = graph.owner.task(member.process).ok()?;
        let resources = row.native().resources();
        if !resources.page.gate().serves_ring() || resources.address != member.address {
            return None;
        }
        Some(member.runtime.clone())
    }

    /// Consume one authenticated external event into the native pending owner.
    /// Admission and the live lifecycle check share the registry guard, so a
    /// recycled member cannot receive an event between lookup and enqueue.
    pub fn admit_external_event<S: NativeProcessService<'a, C, Mm = M>>(
        &self,
        zone: &'a ZoneTables<C>,
        event: carrick_el1_abi::ExternalSignalRecord,
        publishing_slot: SlotId,
        service: &mut S,
    ) -> Result<bool, NativeProcessError> {
        let state = self.state.lock();
        let Some(member) = Self::external_event_member(&state, zone, event) else {
            return Ok(false);
        };
        let claimed_by_member = Self::external_member(&state, zone, event)
            .is_some_and(|claimed| claimed.record == member.record);
        let graph = member.runtime.graph.lock();
        let Ok(row) = graph.owner.task(member.process) else {
            return Ok(false);
        };
        let resources = row.native().resources();
        if !resources.page.gate().serves_ring() || resources.address != member.address {
            return Ok(false);
        }
        let signals = resources.signals().clone();
        let channel = resources.channel.clone();
        let wake_record = member.record;
        let info = match event.source() {
            carrick_el1_abi::ExternalSignalSource::IntervalTimer => Some(
                carrick_syscall_abi::LinuxSiginfo::kernel(event.signal().number()),
            ),
            carrick_el1_abi::ExternalSignalSource::PosixTimer => {
                let timer = event.timer_info();
                Some(carrick_syscall_abi::LinuxSiginfo::timer(
                    event.signal().number(),
                    timer.id,
                    timer.overrun,
                    timer.value,
                ))
            }
            carrick_el1_abi::ExternalSignalSource::Terminal
            | carrick_el1_abi::ExternalSignalSource::HostFault => None,
        };
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(member.control.blocked().0),
        );
        let action = signals.action(event.signal());
        let reserve_for_claimed_member = claimed_by_member
            && !blocked.contains(event.signal())
            && carrick_signal_core::policy::action_interrupts_wait(event.signal(), action);
        match event.scope() {
            carrick_el1_abi::ExternalSignalScope::Process if !reserve_for_claimed_member => {
                signals
                    .enqueue(member.process, event.signal(), info)
                    .map_err(|_| NativeProcessError::Stale)?;
            }
            carrick_el1_abi::ExternalSignalScope::Process
            | carrick_el1_abi::ExternalSignalScope::Thread => {
                signals.enqueue_thread(member.record, event.signal(), info);
            }
        }
        let interrupt = signals.has_deliverable(member.record, blocked);
        let ipc_channel = if interrupt {
            match graph.pending.get(&member.process) {
                Some(PendingContinuation::Ipc(pending)) => Some(pending.channel.clone()),
                _ => None,
            }
        } else {
            None
        };
        drop(graph);
        drop(state);
        if let Some(channel) = ipc_channel {
            publish_signal_channel(
                zone,
                publishing_slot,
                service,
                &channel,
                #[cfg(test)]
                None,
            )?;
        }
        if interrupt {
            request_signal_reschedule(zone, service, wake_record);
        }
        if let Some(channel) = channel {
            publish_signal_channel(
                zone,
                publishing_slot,
                service,
                &channel,
                #[cfg(test)]
                None,
            )?;
        }
        Ok(true)
    }

    /// Drain the one shared transport at a guest boundary. Every published
    /// record is claimed once; stale bindings are refused without selecting a
    /// different task by numeric signal target.
    pub fn drain_external_ingress<S: NativeProcessService<'a, C, Mm = M>>(
        &self,
        zone: &'a ZoneTables<C>,
        queue: &carrick_el1_abi::SharedSignalIngressQueue,
        publishing_slot: SlotId,
        service: &mut S,
    ) -> Result<usize, NativeProcessError> {
        let mut admitted = 0;
        let mut drained = false;
        for _ in 0..carrick_el1_abi::SIGNAL_INGRESS_CAPACITY {
            let Some(event) = queue.take() else {
                break;
            };
            drained = true;
            if self.admit_external_event(zone, event, publishing_slot, service)? {
                admitted += 1;
            }
        }
        if drained && queue.backpressure_waiting() {
            service.request_ingress_producer_boundary();
        }
        Ok(admitted)
    }

    /// The exact admitted process address for a published thread-group
    /// member. The group's page and visible PID prevent MM-only adoption.
    pub fn group_address(
        &self,
        zone: &ZoneTables<C>,
        address: AddressContext<RootGpa>,
        page: &ThreadLifecyclePage,
        visible_pid: u32,
    ) -> Option<AddressContext<RootGpa>> {
        let group = Self::group_key(zone, address, page, visible_pid);
        let (runtime, process) = self.state.lock().groups.get(&group).cloned()?;
        runtime.task_binding(process).map(|binding| binding.address)
    }

    /// Whether any admitted owner retains the thread group of `page` and
    /// `visible_pid` in this carrier, at whatever address incarnation.
    pub fn owns_thread_group(
        &self,
        zone: &ZoneTables<C>,
        page: &ThreadLifecyclePage,
        visible_pid: u32,
    ) -> bool {
        let carrier = core::ptr::from_ref(zone).addr();
        let page = core::ptr::from_ref(page).addr();
        self.state
            .lock()
            .groups
            .range((carrier, 0, 0, 0, 0)..=(carrier, u64::MAX, u64::MAX, usize::MAX, u32::MAX))
            .any(|(&(_, _, _, group_page, pid), _)| group_page == page && pid == visible_pid)
    }

    fn register_child(
        &self,
        parent: &NativeProcessRuntime<'a, M, C>,
        child: NativeChildRegistration,
    ) -> Result<(), NativeProcessError> {
        let parent_key =
            NativeExecutionKey::new(parent.zone, child.parent_binding, child.parent_address)?;
        let mut state = self.state.lock();
        let runtime = state
            .members
            .get(&parent_key)
            .ok_or(NativeProcessError::Stale)?
            .runtime
            .clone();
        if !core::ptr::eq(Arc::as_ptr(&runtime), parent) {
            return Err(NativeProcessError::Stale);
        }
        let child_key = NativeExecutionKey {
            carrier: core::ptr::from_ref(parent.zone).addr(),
            task: NativeThreadIdentity::Issued(child.child),
            mm: child.address.mm.raw().get(),
            thread_generation: child.thread_generation,
            root: child.address.root.address().raw(),
            address_generation: child.address.generation.raw().get(),
        };
        let record_key = Self::record_key(parent.zone, child.record);
        let (page, visible_pid, control) = {
            let graph = runtime.graph.lock();
            let row = graph
                .owner
                .task(child.child)
                .map_err(|_| NativeProcessError::Stale)?;
            (
                row.native().resources().page,
                row.metadata().namespace_pid,
                row.native().resources().control,
            )
        };
        let group_key = Self::group_key(parent.zone, child.address, page, visible_pid);
        if state.members.contains_key(&child_key)
            || state.records.contains_key(&record_key)
            || state.groups.contains_key(&group_key)
        {
            return Err(NativeProcessError::Busy);
        }
        state.members.insert(
            child_key,
            NativeOwnerMember {
                runtime: runtime.clone(),
                process: child.child,
                address: child.address,
                record: child.record,
                control: retain_member_control(control)?,
            },
        );
        state
            .groups
            .insert(group_key, (runtime.clone(), child.child));
        state.by_process.insert(
            (child_key.carrier, child.child),
            (group_key, vec![child_key]),
        );
        state.records.insert(record_key, child_key);
        state
            .members
            .get(&child_key)
            .ok_or(NativeProcessError::Stale)?
            .control
            .commit_native_signal_owner();
        Ok(())
    }

    /// Authenticate an existing thread-lifecycle member before lending its
    /// process owner. An equal MM key without the exact lifecycle publication
    /// cannot confer membership.
    #[inline(never)]
    pub fn register_thread(
        &self,
        source: BornInZoneSource<'a, C>,
        current: &CurrentTask,
        address: AddressContext<RootGpa>,
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
    ) -> Result<Arc<NativeProcessRuntime<'a, M, C>>, NativeProcessError> {
        let binding = super::common_entry::execution_binding(current);
        let key = NativeExecutionKey::new(source.zone, binding, address)?;
        let visible_pid = current.visible_pid().ok_or(NativeProcessError::Stale)?;
        if current.metadata.lifecycle_page.load(Ordering::Acquire)
            != core::ptr::from_ref(page).addr() as u64
            || current.metadata.control_slot.load(Ordering::Acquire)
                != core::ptr::from_ref(control).addr() as u64
        {
            return Err(NativeProcessError::Stale);
        }
        let record = source
            .zone
            .slot(source.slot)
            .current()
            .or_else(|| source.zone.slot(source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        carrick_core::entry::prepare_handoff(binding, source, record)
            .ok_or(NativeProcessError::Stale)?;
        if control.zone_record() != Some(source.zone.record_ref(record)) {
            return Err(NativeProcessError::Stale);
        }
        let (visible_tid, host_issued) = if let Some(entry) = control.entry() {
            let born = page.born_record(entry).ok_or(NativeProcessError::Stale)?;
            let identity = page.identity(entry).ok_or(NativeProcessError::Stale)?;
            if page.control_address(entry) != Some(core::ptr::from_ref(control).addr() as u64)
                || u64::from(identity.tid) != binding.task.raw()
                || identity.thread_serial != binding.thread_generation.raw()
                || born.clone_flags & 0x0001_0000 == 0
            {
                return Err(NativeProcessError::Stale);
            }
            (identity.visible_tid, None)
        } else {
            let issued = IssuedHostThread::authenticate(
                source,
                binding,
                visible_pid,
                page,
                control,
                record,
            )?;
            (issued.visible_tid, Some(issued))
        };
        let group_key = Self::group_key(source.zone, address, page, visible_pid);
        let mut state = self.state.lock();
        if !page.gate().serves_ring() {
            return Err(NativeProcessError::Stale);
        }
        let (runtime, process) = state
            .groups
            .get(&group_key)
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        let record_key = Self::record_key(source.zone, source.zone.record_ref(record));
        if state.members.contains_key(&key) || state.records.contains_key(&record_key) {
            return Err(NativeProcessError::Busy);
        }
        if !state.by_process.contains_key(&(key.carrier, process)) {
            return Err(NativeProcessError::Stale);
        }
        let host_identity = member_host_identity(page, control, binding)?;
        let closing = {
            let mut graph = runtime.graph.lock();
            let row = graph
                .owner
                .task_mut(process)
                .map_err(|_| NativeProcessError::Stale)?;
            let already_owned = if let Some(issued) = host_issued {
                let already_owned = issued.authorize_group(source, row, address, page, control)?;
                if !page.release_adopted_host_birth(
                    carrick_core::terminal::HostThreadRetirementReceipt::from_binding(binding),
                ) {
                    return Err(NativeProcessError::Stale);
                }
                already_owned
            } else {
                let resources = row.native_mut().resources_mut();
                if !core::ptr::eq(resources.page, page) {
                    return Err(NativeProcessError::Stale);
                }
                let imported = resources
                    .members
                    .iter()
                    .find(|member| member.thread.id() == key.task.id());
                if imported.is_some_and(|member| {
                    !core::ptr::eq(member.control.control(), control)
                        || (member.record != source.zone.record_ref(record)
                            && signal_record_exists(source.zone, member.record))
                }) {
                    return Err(NativeProcessError::Stale);
                }
                imported.is_some()
            };
            if row.credentials_for(visible_tid).is_err() {
                let caller_tid = row.metadata().namespace_pid;
                row.spawn_thread(caller_tid, visible_tid)
                    .map_err(|_| NativeProcessError::Invalid)?;
            }
            if already_owned {
                let member = row
                    .native_mut()
                    .resources_mut()
                    .members
                    .iter_mut()
                    .find(|member| member.thread.id() == key.task.id())
                    .ok_or(NativeProcessError::Stale)?;
                member.thread = key.task;
                member.record = source.zone.record_ref(record);
                member.expected_host = host_identity;
            } else {
                let retained = retain_member_control(control)?;
                retained.commit_registration();
                row.native_mut().resources_mut().members.push(NativeMember {
                    thread: key.task,
                    process,
                    zone: source.zone,
                    record: source.zone.record_ref(record),
                    control: retained,
                    expected_host: host_identity,
                });
            }
            row.native().resources().sync_non_interrupting_signals();
            graph.pending_exit.contains_key(&process)
        };
        state.members.insert(
            key,
            NativeOwnerMember {
                runtime: runtime.clone(),
                process,
                address,
                record: source.zone.record_ref(record),
                control: retain_member_control(control)?,
            },
        );
        state
            .by_process
            .get_mut(&(key.carrier, process))
            .ok_or(NativeProcessError::Stale)?
            .1
            .push(key);
        state.records.insert(record_key, key);
        state
            .members
            .get(&key)
            .ok_or(NativeProcessError::Stale)?
            .control
            .commit_native_signal_owner();
        drop(state);
        if closing {
            let wait = NativeBucketWait {
                lifetime: core::marker::PhantomData,
                #[cfg(test)]
                probe: None,
            };
            let _ = source.zone.claim_for_host(
                source.zone.record_ref(record),
                None,
                Handback::Cancelled,
                &wait,
            );
        }
        Ok(runtime)
    }

    fn unregister_member(
        &self,
        runtime: &NativeProcessRuntime<'a, M, C>,
        process: TaskKey,
        record: RecordRef,
    ) {
        let mut state = self.state.lock();
        let carrier = core::ptr::from_ref(runtime.zone).addr();
        let key = state.members.iter().find_map(|(key, member)| {
            (key.carrier == carrier && member.process == process && member.record == record)
                .then_some(*key)
        });
        if let Some(key) = key {
            state.members.remove(&key);
            state
                .records
                .remove(&Self::record_key(runtime.zone, record));
            if let Some((_, keys)) = state.by_process.get_mut(&(carrier, process)) {
                keys.retain(|candidate| *candidate != key);
            }
        }
    }

    fn unregister_process(&self, runtime: &NativeProcessRuntime<'a, M, C>, process: TaskKey) {
        let mut state = self.state.lock();
        let carrier = core::ptr::from_ref(runtime.zone).addr();
        let Some((group, members)) = state.by_process.remove(&(carrier, process)) else {
            return;
        };
        for key in members {
            if let Some(member) = state.members.remove(&key) {
                state
                    .records
                    .remove(&Self::record_key(runtime.zone, member.record));
            }
        }
        state.groups.remove(&group);
    }
}

/// Proof that a non-pooled thread carries an exact host-issued execution
/// binding and retained control slot for an already-admitted thread group.
#[derive(Clone, Copy)]
struct IssuedHostThread {
    key: TaskKey,
    visible_pid: u32,
    visible_tid: u32,
    file_table: u64,
    record: RecordRef,
}

impl IssuedHostThread {
    fn authenticate<C: ProcessContext>(
        source: BornInZoneSource<'_, C>,
        binding: ExecutionBinding,
        visible_pid: u32,
        page: &ThreadLifecyclePage,
        control: &ThreadControlSlot,
        record: carrick_sched_core::RecordId,
    ) -> Result<Self, NativeProcessError> {
        if !binding.issued() || control.entry().is_some() {
            return Err(NativeProcessError::Stale);
        }
        let key = NativeThreadIdentity::from_binding(binding)?
            .issued()
            .ok_or(NativeProcessError::Stale)?;
        let visible_tid = control.visible_tid().ok_or(NativeProcessError::Stale)?;
        if control.host_birth_identity()
            != Some(carrick_core::terminal::HostThreadRetirementReceipt::from_binding(binding))
            || !(0..carrick_el1_abi::THREAD_POOL_ENTRIES).any(|index| {
                page.host_birth_identity(index)
                    == Some(
                        carrick_core::terminal::HostThreadRetirementReceipt::from_binding(binding),
                    )
            })
        {
            return Err(NativeProcessError::Stale);
        }
        let record_ref = source.zone.record_ref(record);
        if control.zone_record() != Some(record_ref) {
            return Err(NativeProcessError::Stale);
        }
        let identity = source.zone.record(record).identity();
        if identity.tid != binding.task.raw()
            || identity.generation != binding.generation.raw()
            || identity.serial != binding.thread_generation.raw()
            || identity.mm != binding.mm.raw()
            || identity.lifecycle_page != core::ptr::from_ref(page).addr() as u64
            || identity.control_slot != core::ptr::from_ref(control).addr() as u64
        {
            return Err(NativeProcessError::Stale);
        }
        Ok(Self {
            key,
            visible_pid,
            visible_tid,
            file_table: identity.file_table,
            record: record_ref,
        })
    }

    fn authorize_group<'a, M: Clone, C: ProcessContext>(
        self,
        source: BornInZoneSource<'a, C>,
        row: &NativeIdentityTask<'a, M, C>,
        address: AddressContext<RootGpa>,
        page: &ThreadLifecyclePage,
        control: &ThreadControlSlot,
    ) -> Result<bool, NativeProcessError> {
        let namespace_pid = row.metadata().namespace_pid;
        if self.visible_pid != namespace_pid || self.visible_tid == namespace_pid {
            return Err(NativeProcessError::Stale);
        }
        let resources = row.native().resources();
        if !core::ptr::eq(resources.page, page)
            || resources.address != address
            || resources.file_table != self.file_table
            || core::ptr::eq(resources.control, control)
            || !resources.page.gate().serves_ring()
            || resources.page.live() <= 1
        {
            return Err(NativeProcessError::Stale);
        }
        if let Some(existing) = resources
            .members
            .iter()
            .find(|member| member.thread.id() == self.key.id)
        {
            if existing.thread != NativeThreadIdentity::Issued(self.key)
                || !core::ptr::eq(existing.control.control(), control)
                || (existing.record != self.record
                    && signal_record_exists(source.zone, existing.record))
            {
                return Err(NativeProcessError::Stale);
            }
            return Ok(true);
        }
        if resources.members.iter().any(|member| {
            core::ptr::eq(member.control.control(), control) || member.record == self.record
        }) || resources.members.len() >= resources.page.live() as usize
            || row.credentials_for(self.visible_tid).is_ok()
        {
            return Err(NativeProcessError::Stale);
        }
        Ok(false)
    }
}

impl<'a, M: Clone, C: ProcessContext> Default for NativeProcessRegistry<'a, M, C> {
    fn default() -> Self {
        Self::new()
    }
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
    resources.sync_non_interrupting_signals();
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
    pub fn signals(
        &self,
    ) -> &NativeProcessSignals<carrick_personality_linux::abi::signal::LinuxSiginfo> {
        &self.signals
    }
    pub fn signals_mut(
        &mut self,
    ) -> &mut NativeProcessSignals<carrick_personality_linux::abi::signal::LinuxSiginfo> {
        &mut self.signals
    }
    pub fn sync_non_interrupting_signals(&self) {
        let non_interrupting = self.signals.non_interrupting_signals();
        let mask = carrick_el1_abi::BlockedMask(non_interrupting.bits());
        self.control.set_non_interrupting(mask);
        if let Some(tid) = self.control.visible_tid()
            && let Ok(tid) = i32::try_from(tid)
        {
            carrick_signal_core::wait::publish_non_interrupting_for(tid, non_interrupting);
        }
        for member in &self.members {
            member.control.set_non_interrupting(mask);
            carrick_signal_core::wait::publish_non_interrupting_for(
                member.thread.id().raw(),
                non_interrupting,
            );
            if let Some(tid) = member.control.visible_tid()
                && let Ok(tid) = i32::try_from(tid)
            {
                carrick_signal_core::wait::publish_non_interrupting_for(tid, non_interrupting);
            }
        }
    }
}
impl<'a, M: Clone, C: ProcessContext> NativeProcessRuntime<'a, M, C> {
    #[cfg(test)]
    pub(super) fn install_closing_race_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        *self.closing_race_hook.lock() = Some(hook);
    }
    #[cfg(test)]
    pub(super) fn install_pool_control_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        *self.pool_control_hook.lock() = Some(hook);
    }
    #[cfg(test)]
    pub(super) fn install_pool_retained_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        *self.pool_retained_hook.lock() = Some(hook);
    }
    #[cfg(test)]
    pub(super) fn install_settle_race_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        *self.settle_race_hook.lock() = Some(hook);
    }
    #[cfg(test)]
    pub(super) fn install_raw_exit_after_commit_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        *self.raw_exit_after_commit_hook.lock() = Some(hook);
    }
    pub fn zone(&self) -> &'a ZoneTables<C> {
        self.zone
    }
    /// Snapshot the sighand of the exact faulting task incarnation.
    pub fn current_signals(
        &self,
        current: &CurrentTask,
    ) -> Option<NativeProcessSignals<carrick_personality_linux::abi::signal::LinuxSiginfo>> {
        let binding = super::common_entry::execution_binding(current);
        let page = current.metadata.lifecycle_page.load(Ordering::Acquire);
        let control_address = current.metadata.control_slot.load(Ordering::Acquire);
        let graph = self.graph.lock();
        let (_, row) = graph.owner.tasks().iter().find(|(_, row)| {
            let resources = row.native().resources();
            resources.address.mm.raw().get() == binding.mm.raw()
                && resources.page as *const _ as u64 == page
        })?;
        let resources = row.native().resources();
        let control = owned_control(resources.page, resources.control, control_address)?;
        let record = control
            .zone_record()
            .or_else(|| core::ptr::eq(resources.control, control).then_some(resources.record))?;
        if !signal_record_exists(self.zone, record) {
            return None;
        }
        let thread = self.zone.record(record.id).identity();
        (thread.tid == binding.task.raw()
            && thread.serial == binding.thread_generation.raw()
            && thread.generation == binding.generation.raw()
            && thread.mm == binding.mm.raw()
            && thread.control_slot == control as *const _ as u64)
            .then(|| resources.signals().clone())
    }
    /// Import only retained, published thread records. The lifecycle census
    /// must account for exactly these members plus the leader; admission never
    /// edits the count or supplies missing host tasks.
    fn imported_members(
        zone: &'a ZoneTables<C>,
        page: &'a ThreadLifecyclePage,
        leader: &'a ThreadControlSlot,
        process: TaskKey,
        mm: u64,
        file_table: u64,
    ) -> Result<Vec<(NativeMember<'a, C>, NonZeroU32, u64)>, NativeProcessError> {
        let mut members = Vec::new();
        for index in 0..page.entry_count() {
            let (generation, state) = page.state(index).ok_or(NativeProcessError::Stale)?;
            if !matches!(
                state,
                carrick_el1_abi::EntryState::Born | carrick_el1_abi::EntryState::Published
            ) {
                continue;
            }
            let entry = EntryRef::new(index as u32, generation);
            let identity = page.identity(entry).ok_or(NativeProcessError::Stale)?;
            let born = page.born_record(entry).ok_or(NativeProcessError::Stale)?;
            let address = page
                .control_address(entry)
                .filter(|address| {
                    *address != 0
                        && address.is_multiple_of(core::mem::align_of::<ThreadControlSlot>() as u64)
                })
                .ok_or(NativeProcessError::Stale)?;
            let control = owned_control(page, leader, address).ok_or(NativeProcessError::Stale)?;
            let record = control.zone_record().ok_or(NativeProcessError::Stale)?;
            if !signal_record_exists(zone, record) {
                return Err(NativeProcessError::Stale);
            }
            let retained = zone.record(record.id).identity();
            let visible = NonZeroU32::new(identity.visible_tid).ok_or(NativeProcessError::Stale)?;
            let member_binding = ExecutionBinding {
                task: carrick_core_abi::EntryTaskKey::from_raw(u64::from(identity.tid)),
                generation: carrick_core_abi::EntryGeneration::from_raw(retained.generation),
                mm: carrick_core_abi::EntryMmKey::from_raw(mm),
                thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(
                    identity.thread_serial,
                ),
            };
            let thread = NativeThreadIdentity::from_binding(member_binding)?;
            if born.clone_flags & 0x0001_0000 == 0
                || retained.tid != u64::from(identity.tid)
                || retained.serial != identity.thread_serial
                || retained.mm != mm
                || retained.file_table != file_table
                || retained.lifecycle_page != page as *const _ as u64
                || retained.control_slot != address
                || control.visible_tid() != Some(visible.get())
                || thread.id() == process.id
                || members.iter().any(
                    |(member, tid, _): &(NativeMember<'a, C>, NonZeroU32, u64)| {
                        member.thread.id() == thread.id() || *tid == visible
                    },
                )
            {
                return Err(NativeProcessError::Stale);
            }
            members.push((
                NativeMember {
                    thread,
                    process,
                    zone,
                    record,
                    control: retain_member_control(control)?,
                    expected_host: member_host_identity(page, control, member_binding)?,
                },
                visible,
                identity.thread_serial,
            ));
        }
        if page.live() as usize != 1 + members.len() || page.claimed_count() != 0 {
            return Err(NativeProcessError::Invalid);
        }
        Ok(members)
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
            .and_then(|id| carrick_personality_linux::identity::task_id_from_linux_pid(id).ok())
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
        let imported = Self::imported_members(
            source.zone,
            page,
            control,
            key,
            binding.mm.raw(),
            identity.file_table,
        )?;
        let ns = Arc::new(SpinLock::new(NamespaceState::new(1, i32::MAX, id.raw())));
        let visible_namespace = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
        let (task_claim, mut thread_claim, root_roles) = {
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
        {
            let mut n = ns.lock();
            for (member, visible_tid, _) in &imported {
                let number = n
                    .reserve_exact(member.thread.id().raw(), ClaimKind::Thread)
                    .map_err(|_| NativeProcessError::Exhausted)?;
                n.advance_visible_past(
                    visible_namespace,
                    VisibleIdentity::from_existing_member(*visible_tid),
                )
                .ok_or(NativeProcessError::Exhausted)?;
                thread_claim.claims.push((number, ClaimKind::Thread));
            }
        }
        let serials = SerialAllocator::new();
        serials
            .advance_past(
                NonZeroU64::new(
                    binding
                        .generation
                        .raw()
                        .max(binding.thread_generation.raw())
                        .max(binding.mm.raw())
                        .max(identity.file_table)
                        .max(
                            imported
                                .iter()
                                .map(|(member, _, serial)| {
                                    member
                                        .thread
                                        .issued()
                                        .map_or(0, |key| key.serial.raw())
                                        .max(*serial)
                                })
                                .max()
                                .unwrap_or(0),
                        ),
                )
                .ok_or(NativeProcessError::Invalid)?,
            )
            .ok_or(NativeProcessError::Exhausted)?;
        let file_table = if identity.file_table != 0 {
            identity.file_table
        } else {
            1
        };
        let mut members = vec![NativeMember {
            thread: NativeThreadIdentity::Issued(key),
            process: key,
            zone: source.zone,
            record: source.zone.record_ref(record),
            control: retain_member_control(control)?,
            expected_host: carrick_core::terminal::HostThreadRetirementReceipt::from_binding(
                binding,
            ),
        }];
        members.extend(imported.iter().map(|(member, _, _)| member.clone()));
        let resources = NativeResources {
            _control_custody: carrick_core::lifecycle::MemberControlCustody::retain(control)
                .map_err(|_| NativeProcessError::Stale)?,
            zone: source.zone,
            record: source.zone.record_ref(record),
            control,
            page,
            members,
            mm,
            address,
            pending_child_tid: None,
            signals: NativeProcessSignals::fresh_root(key),
            _thread_claim: thread_claim,
            channel: None,
            usage: TaskRusage::default(),
            file_table,
        };
        let mut owner = Owner::new();
        let mut initial = GuestTask::new(
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
        );
        for (_, tid, _) in &imported {
            initial
                .spawn_thread(visible.get(), tid.get())
                .map_err(|_| NativeProcessError::Invalid)?;
        }
        owner
            .seed_initial(initial)
            .map_err(|_| NativeProcessError::Invalid)?;

        #[cfg(target_arch = "x86_64")]
        let uts = carrick_personality_linux::sysinfo::LinuxUtsname::carrick_x86_64();
        #[cfg(not(target_arch = "x86_64"))]
        let uts = carrick_personality_linux::sysinfo::LinuxUtsname::carrick_aarch64();
        if !control.publish_visible_tid(visible.get()) {
            return Err(NativeProcessError::Stale);
        }
        for member in &owner
            .task(key)
            .map_err(|_| NativeProcessError::Stale)?
            .native()
            .resources()
            .members
        {
            member.control.commit_registration();
        }
        let ipc = Arc::new(SpinLock::new(IpcNamespace::default()));
        let ipc_channels = Arc::new(SpinLock::new(Vec::new()));
        Ok(Self {
            graph: SpinLock::new(Graph {
                owner,
                root_key: key,
                namespace: ns,
                visible_namespace,
                serials,
                pending: BTreeMap::new(),
                pending_exit: BTreeMap::new(),
                signal_waits: BTreeMap::new(),
                suspend_masks: BTreeMap::new(),
                _root_roles: root_roles,
                uts,
                ipc,
            }),
            zone: source.zone,
            ipc_channels,
            #[cfg(test)]
            signal_check_hook: SpinLock::new(None),
            #[cfg(test)]
            closing_race_hook: SpinLock::new(None),
            #[cfg(test)]
            pool_control_hook: SpinLock::new(None),
            #[cfg(test)]
            pool_retained_hook: SpinLock::new(None),
            #[cfg(test)]
            settle_race_hook: SpinLock::new(None),
            #[cfg(test)]
            raw_exit_after_commit_hook: SpinLock::new(None),
            registry: SpinLock::new(None),
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
        let thread = source.zone.record(record).identity();
        let mut graph = self.graph.lock();
        let key = graph
            .owner
            .tasks()
            .iter()
            .find_map(|(_, row)| {
                let resources = row.native().resources();
                (resources.address.mm.raw().get() == thread.mm
                    && resources.page as *const _ as u64 == thread.lifecycle_page)
                    .then_some(row.key())
            })
            .ok_or(NativeProcessError::Stale)?;
        let row = graph
            .owner
            .task_mut(key)
            .map_err(|_| NativeProcessError::Stale)?;
        if !words.authenticates(row.native().resources().address) {
            return Err(NativeProcessError::Stale);
        }
        let control = owned_control(
            row.native().resources().page,
            row.native().resources().control,
            thread.control_slot,
        )
        .ok_or(NativeProcessError::Stale)?;
        control.bind_zone_record(source.zone.record_ref(record));
        let caller_address = row.native().resources().address;
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
        let owner_continuation = graph
            .pending_exit
            .get(&key)
            .is_some_and(|pending| core::ptr::eq(pending.caller.control(), control));
        drop(graph);
        Ok(NativeProcessEntry {
            runtime: self,
            source,
            current,
            binding,
            record: source.zone.record_ref(record),
            control,
            _control_custody: Some(
                carrick_core::lifecycle::MemberControlCustody::retain(control)
                    .map_err(|_| NativeProcessError::Stale)?,
            ),
            key,
            caller_address,
            words,
            service,
            handoff: None,
            root_exit: None,
            run_failure: None,
            #[cfg(test)]
            publication_wait_probe: None,
            #[cfg(test)]
            exit_notification_probe: None,
            calling_tid,
            slot,
            interrupted_child_wait: None,
            owner_continuation,
        })
    }
    /// Enter through the exact process registry. A non-leader thread retains
    /// its own execution binding and context, while process operations name
    /// the graph row of its authenticated thread group.
    #[inline(always)]
    pub fn enter_registered<'r, S: NativeProcessService<'a, C, Mm = M>>(
        &'r self,
        registry: &NativeProcessRegistry<'a, M, C>,
        source: BornInZoneSource<'a, C>,
        current: &'a CurrentTask,
        address: AddressContext<RootGpa>,
        words: C,
        service: &'r mut S,
    ) -> Result<NativeProcessEntry<'r, 'a, M, C, S>, NativeProcessError> {
        let (binding, record, member_control, process, calling_tid, owner_continuation) =
            self.authenticate_registered(registry, source, current, address, &words)?;
        Ok(NativeProcessEntry {
            runtime: self,
            source,
            current,
            binding,
            record,
            control: member_control,
            _control_custody: Some(
                carrick_core::lifecycle::MemberControlCustody::retain(member_control)
                    .map_err(|_| NativeProcessError::Stale)?,
            ),
            key: process,
            caller_address: address,
            words,
            service,
            handoff: None,
            root_exit: None,
            run_failure: None,
            #[cfg(test)]
            publication_wait_probe: None,
            #[cfg(test)]
            exit_notification_probe: None,
            calling_tid,
            slot: Some(member_control),
            interrupted_child_wait: None,
            owner_continuation,
        })
    }

    #[inline(never)]
    fn authenticate_registered(
        &self,
        registry: &NativeProcessRegistry<'a, M, C>,
        source: BornInZoneSource<'a, C>,
        current: &'a CurrentTask,
        address: AddressContext<RootGpa>,
        words: &C,
    ) -> Result<
        (
            ExecutionBinding,
            RecordRef,
            &'a ThreadControlSlot,
            TaskKey,
            u32,
            bool,
        ),
        NativeProcessError,
    > {
        if !core::ptr::eq(source.zone, self.zone) {
            return Err(NativeProcessError::Stale);
        }
        let binding = super::common_entry::execution_binding(current);
        let member_key = NativeExecutionKey::new(source.zone, binding, address)?;
        let member = registry
            .state
            .lock()
            .members
            .get(&member_key)
            .cloned()
            .ok_or(NativeProcessError::Stale)?;
        if !core::ptr::eq(Arc::as_ptr(&member.runtime), self)
            || !words.authenticates(member.address)
        {
            return Err(NativeProcessError::Stale);
        }
        let record = source
            .zone
            .slot(source.slot)
            .current()
            .or_else(|| source.zone.slot(source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        carrick_core::entry::prepare_handoff(binding, source, record)
            .ok_or(NativeProcessError::Stale)?;
        let mut graph = self.graph.lock();
        let row = graph
            .owner
            .task_mut(member.process)
            .map_err(|_| NativeProcessError::Stale)?;
        let resources = row.native().resources();
        if resources.address.mm != address.mm
            || resources.address.root != address.root
            || current.metadata.lifecycle_page.load(Ordering::Acquire)
                != core::ptr::from_ref(resources.page).addr() as u64
            || current.visible_pid() != Some(row.metadata().namespace_pid)
        {
            return Err(NativeProcessError::Stale);
        }
        let member_control = resources
            .members
            .iter()
            .find(|m| m.thread == member_key.task)
            .map(|m| m.control.control())
            .ok_or(NativeProcessError::Stale)?;
        if current.metadata.control_slot.load(Ordering::Acquire)
            != member_control as *const _ as u64
        {
            return Err(NativeProcessError::Stale);
        }
        let record_ref = source.zone.record_ref(record);
        member_control.bind_zone_record(record_ref);
        if core::ptr::eq(member_control, resources.control) {
            if resources.record != record_ref {
                return Err(NativeProcessError::Stale);
            }
            *row.context_mut() = *words;
        }
        let calling_tid = member_control
            .visible_tid()
            .ok_or(NativeProcessError::Stale)?;
        row.credentials_for(calling_tid)
            .map_err(|_| NativeProcessError::Stale)?;
        let owner_continuation = graph
            .pending_exit
            .get(&member.process)
            .is_some_and(|pending| core::ptr::eq(pending.caller.control(), member_control));
        drop(graph);
        Ok((
            binding,
            record_ref,
            member_control,
            member.process,
            calling_tid,
            owner_continuation,
        ))
    }
    pub fn namespace_child_key(&self, caller: TaskKey, visible: u32) -> Option<TaskKey> {
        self.graph
            .lock()
            .owner
            .namespace_child_key(caller, visible)
            .ok()
            .flatten()
    }
    /// Resolve the process and exact saved thread context.
    ///
    /// # Safety
    /// The caller must hold exclusive execution custody of this record after
    /// scheduler selection, so no other executor can mutate its saved context.
    pub unsafe fn record_binding(&self, record: RecordRef) -> Option<NativeRecordBinding<M, C>> {
        let live = self.zone.live(record)?;
        let identity = live.identity();
        let graph = self.graph.lock();
        let (_, row) = graph.owner.tasks().iter().find(|(_, row)| {
            let resources = row.native().resources();
            resources.address.mm.raw().get() == identity.mm
                && resources.page as *const _ as u64 == identity.lifecycle_page
        })?;
        let resources = row.native().resources();
        // SAFETY: the caller selected this exact Queued/OnCpu record after the
        // scheduler handed it exclusive context custody. Fresh births initialized it.
        let words = unsafe { *live.ctx_mut() };
        Some(NativeRecordBinding {
            key: row.key(),
            visible_pid: row.metadata().namespace_pid,
            mm: resources.mm.clone(),
            address: resources.address,
            words,
            record,
        })
    }

    /// Resolve only the process identity needed to re-enter a selected record.
    /// The saved register words remain in the exclusively owned zone record.
    ///
    /// # Safety
    /// The scheduler must own the selected record until entry completes.
    pub unsafe fn resume_visible_pid(&self, record: RecordRef) -> Option<u32> {
        let live = self.zone.live(record)?;
        let identity = live.identity();
        let graph = self.graph.lock();
        let (_, row) = graph.owner.tasks().iter().find(|(_, row)| {
            let resources = row.native().resources();
            resources.address.mm.raw().get() == identity.mm
                && resources.page as *const _ as u64 == identity.lifecycle_page
        })?;
        Some(row.metadata().namespace_pid)
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
    current: &'a CurrentTask,
    binding: ExecutionBinding,
    record: RecordRef,
    control: &'a ThreadControlSlot,
    _control_custody: Option<carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot>>,
    key: TaskKey,
    caller_address: AddressContext<RootGpa>,
    words: C,
    service: &'r mut S,
    handoff: Option<EntryHandoffReceipt<C>>,
    root_exit: Option<LinuxWaitStatus>,
    run_failure: Option<carrick_core_abi::NativeRunFailureReason>,
    #[cfg(test)]
    publication_wait_probe: Option<&'r (dyn Fn(u32) + Sync)>,
    #[cfg(test)]
    exit_notification_probe: Option<&'r (dyn Fn() + Sync)>,
    calling_tid: u32,
    slot: Option<&'a ThreadControlSlot>,
    interrupted_child_wait: Option<Box<C>>,
    // Captured by native admission under its existing graph guard. Ordinary
    // syscall dispatch does not acquire another graph lock for this checkpoint.
    owner_continuation: bool,
}

impl<'r, 'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'r, 'a, M, C, S>
{
    /// Test pending native work before the ISA saves FP/SIMD for delivery.
    /// A suspended mask needs its restoration even if no signal is pending.
    pub fn signal_checkpoint_needed(&self) -> bool {
        if self.control.forwarded_wait_mask_armed() {
            return true;
        }
        let graph = self.runtime.graph.lock();
        let Ok(row) = graph.owner.task(self.key) else {
            return true;
        };
        if graph.suspend_masks.contains_key(&self.record) {
            return true;
        }
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
        );
        row.native()
            .resources()
            .signals()
            .has_deliverable(self.record, blocked)
    }
}
// Enrollment and committed settlement wait only for another party's short
// bucket section. No graph guard is retained while acquiring this lock.
struct NativeBucketWait<'a> {
    lifetime: core::marker::PhantomData<&'a ()>,
    #[cfg(test)]
    probe: Option<&'a (dyn Fn(u32) + Sync)>,
}
impl carrick_sched_core::ShortLockWait for NativeBucketWait<'_> {
    fn wait_short(&self, _attempt: u32) {
        #[cfg(test)]
        if let Some(probe) = self.probe {
            probe(_attempt);
        }
        core::hint::spin_loop();
    }
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
    pub fn take_run_failure(&mut self) -> Option<carrick_core_abi::NativeRunFailureReason> {
        self.run_failure.take()
    }
    fn run_failed(&mut self, reason: carrick_core_abi::NativeRunFailureReason) -> LifecycleOutcome {
        self.run_failure = Some(reason);
        if let Some(record) = self
            .source
            .zone
            .slot(self.source.slot)
            .current()
            .or_else(|| self.source.zone.slot(self.source.slot).host_record())
        {
            self.handoff = carrick_core::entry::retire_current(self.binding, self.source, record);
        }
        // No graph exit or MM retirement is claimed. Even if lane retirement
        // refuses, the authenticated carrier report stops this incomplete run.
        LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            result: SyscallResult::new(0),
        }
    }
    fn send_thread_signal(
        &mut self,
        group: Option<NonZeroU32>,
        selector: carrick_personality_linux::signal::SignalThreadSelector,
        request: carrick_personality_linux::signal::SignalRequest,
        info: carrick_personality_linux::signal::SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        use carrick_personality_linux::abi::signal::LINUX_ESRCH;
        let sig = request.number();
        let visible = selector
            .positive()
            .ok_or(carrick_syscall_abi::LINUX_EINVAL)?;
        let graph = self.runtime.graph.lock();
        let mut selected = None;
        for row in graph.owner.tasks().values() {
            if group.is_some_and(|group| group.get() != row.metadata().namespace_pid) {
                continue;
            }
            let resources = row.native().resources();
            if visible.get() == row.metadata().namespace_pid {
                let record = if row.key() == self.key {
                    self.record
                } else {
                    resources.control.zone_record().unwrap_or(resources.record)
                };
                if signal_record_exists(self.source.zone, record) {
                    selected = Some((
                        row.key(),
                        record,
                        resources.signals().clone(),
                        resources.channel.clone(),
                    ));
                    break;
                }
            }
            for index in 0..resources.page.entry_count() {
                let Some((generation, state)) = resources.page.state(index) else {
                    continue;
                };
                if !matches!(
                    state,
                    carrick_el1_abi::EntryState::Born | carrick_el1_abi::EntryState::Published
                ) {
                    continue;
                }
                let entry = EntryRef::new(index as u32, generation);
                let Some(identity) = resources.page.identity(entry) else {
                    continue;
                };
                if identity.visible_tid != visible.get() {
                    continue;
                }
                let Some(address) = resources.page.control_address(entry) else {
                    continue;
                };
                // SAFETY: the lifecycle owner retains and authenticates this control
                // address for this exact nonretired entry incarnation.
                let control = unsafe { &*(address as *const ThreadControlSlot) };
                if control.entry() != Some(entry) {
                    continue;
                }
                let Some(record) = control.zone_record() else {
                    continue;
                };
                let Some(live) = self.source.zone.live(record) else {
                    continue;
                };
                let thread = live.identity();
                if thread.tid != u64::from(identity.tid)
                    || thread.serial != identity.thread_serial
                    || thread.mm != resources.address.mm.raw().get()
                    || thread.lifecycle_page != resources.page as *const _ as u64
                    || thread.control_slot != address
                {
                    continue;
                }
                selected = Some((
                    row.key(),
                    record,
                    resources.signals().clone(),
                    resources.channel.clone(),
                ));
                break;
            }
            if selected.is_some() {
                break;
            }
        }
        let (target_key, record, signals, channel) = selected.ok_or(LINUX_ESRCH)?;
        use carrick_personality_linux::signal::SignalTargetScope;
        info.check_target(if target_key == self.key {
            SignalTargetScope::CallingProcess
        } else {
            SignalTargetScope::OtherProcess
        })?;
        if sig == 0 {
            return Ok(());
        }
        let Some(signal) = request.signal() else {
            return Ok(());
        };
        let sender = graph
            .owner
            .task(self.key)
            .map_err(|_| LINUX_ESRCH)?
            .metadata()
            .namespace_pid;
        let info = info.payload(signal).unwrap_or_else(|| {
            carrick_personality_linux::abi::signal::LinuxSiginfo::kill(
                sig,
                carrick_personality_linux::abi::signal::LINUX_SI_TKILL,
                sender as i32,
                0,
            )
        });
        signals.enqueue_thread(record, signal, Some(info));
        let target = self.source.zone.record(record.id).identity();
        let blocked = graph
            .owner
            .tasks()
            .iter()
            .find_map(|(_, row)| {
                let resources = row.native().resources();
                (resources.address.mm.raw().get() == target.mm
                    && resources.page as *const _ as u64 == target.lifecycle_page)
                    .then(|| owned_control(resources.page, resources.control, target.control_slot))
                    .flatten()
            })
            .map(|control| {
                carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                    carrick_signal_core::SignalSet::from_bits(control.blocked().0),
                )
            });
        let interrupt = blocked.is_some_and(|blocked| signals.has_deliverable(record, blocked));
        let ipc_channel = if interrupt {
            match graph.pending.get(&target_key) {
                Some(PendingContinuation::Ipc(pending)) => Some(pending.channel.clone()),
                _ => None,
            }
        } else {
            None
        };
        drop(graph);
        if let Some(channel) = ipc_channel {
            self.publish_channel(&channel)
                .map_err(|e| carrick_syscall_abi::LinuxErrno::new(-e.errno() as i32))?;
        }
        if interrupt {
            self.interrupt_signal_record(record);
        }
        if let Some(channel) = channel {
            self.publish_channel(&channel)
                .map_err(|e| carrick_syscall_abi::LinuxErrno::new(-e.errno() as i32))?;
        }
        Ok(())
    }

    // Dependency: owned interrupt cancellation. Parked futex/object operations
    // retain their pending signals until their owner resumes; an IPI does not
    // cancel their operation or release its queue/timer custody.
    fn interrupt_signal_record(&mut self, record: RecordRef) {
        request_signal_reschedule(self.source.zone, self.service, record);
    }

    pub fn take_root_exit(&mut self) -> Option<LinuxWaitStatus> {
        self.root_exit.take()
    }
    pub fn task_id(&self) -> u32 {
        self.key.id.raw() as u32
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
            class: carrick_personality_linux::lifecycle::wait_child_class(options),
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
                    let ch = channel.clone();
                    match self.park_continuation(
                        &ch,
                        precheck.wake_generation(),
                        PendingContinuation::Wait(PendingWait {
                            caller: self.key,
                            query,
                            status,
                            precheck,
                            channel,
                        }),
                    )? {
                        ContinuationPark::Rescan => continue,
                        ContinuationPark::Interrupted => {
                            return Ok(returned(carrick_syscall_abi::LINUX_EINTR.guest_retval()));
                        }
                        ContinuationPark::Parked => {}
                    }
                    return Ok(LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        result: SyscallResult::new(0),
                    });
                }
            }
        }
    }
    /// Publish a synchronous fault payload through this exact process owner.
    pub fn force_sigsegv_info(
        &mut self,
        blocked: carrick_signal_core::policy::SigBlockMask,
        mut info: carrick_syscall_abi::LinuxSiginfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        info.si_signo = carrick_signal_core::policy::Signal::SEGV.number();
        let graph = self.runtime.graph.lock();
        let row = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_syscall_abi::LINUX_ESRCH)?;
        let resources = row.native().resources();
        resources
            .signals()
            .force_sigsegv(self.record, blocked, Some(info));
        resources.sync_non_interrupting_signals();
        Ok(())
    }

    /// Copy a signal frame through the same exact-MM COW authority as wait status.
    pub fn copy_signal_frame(
        &mut self,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        let mm = self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?
            .native()
            .resources()
            .mm
            .clone();
        self.service.copy_signal_bytes(&mm, address, bytes)
    }
    fn park_signal_wait(
        &mut self,
        kind: PendingSignalKind,
        channel: Arc<WaitChannel>,
        observed: carrick_sched_core::process::wait::TaskWakeGeneration,
        deadline: Option<carrick_guest_arch::Deadline>,
    ) -> Result<bool, NativeProcessError> {
        let zone = self.source.zone;
        let record = zone
            .slot(self.source.slot)
            .current()
            .or_else(|| zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        let start = carrick_core::entry::prepare_handoff(self.binding, self.source, record)
            .ok_or(NativeProcessError::Stale)?;
        let address = WaitChannel::address(&channel);
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
            &NativeBucketWait {
                lifetime: core::marker::PhantomData,
                #[cfg(test)]
                probe: self.publication_wait_probe,
            },
        );
        if channel.generation.generation() != observed {
            return Ok(false);
        }
        let sequence = zone.next_seq(record);
        self.arm_park_timer(record, sequence, deadline)?;
        zone.enqueue(&guard, record, sequence, channel.mm, address, u32::MAX, 0)
            .map_err(|_| {
                zone.cancel_timer_admission(self.record);
                NativeProcessError::Exhausted
            })?;
        // SAFETY: this exact record is still authenticated OnCpu under its bucket guard.
        unsafe { *zone.record(record).ctx_mut() = self.words };
        self.runtime.graph.lock().signal_waits.insert(
            self.record,
            PendingSignalWait {
                kind,
                channel,
                deadline,
            },
        );
        let receipt = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_el1_abi::EntryRecordGeneration(sequence),
        );
        if receipt.is_none() {
            self.runtime.graph.lock().signal_waits.remove(&self.record);
            zone.cancel_timer_admission(self.record);
            return Err(NativeProcessError::Busy);
        }
        drop(guard);
        zone.clear_current(self.source.slot);
        self.handoff = receipt;
        Ok(true)
    }
    fn resume_signal_wait(
        &mut self,
        pending: PendingSignalWait,
    ) -> Result<LifecycleOutcome, NativeProcessError> {
        loop {
            // A publication after this snapshot must invalidate enrollment.
            let observed = pending.channel.generation.generation();
            let graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            let resources = row.native().resources();
            let signals = resources.signals().clone();
            let mm = resources.mm.clone();
            let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
            );
            drop(graph);
            if let PendingSignalKind::Wait { set, info } = pending.kind
                && let Some((signal, payload)) = signals.take_timedwait(self.record, set)
            {
                if info.raw() != 0 {
                    let payload = payload.unwrap_or_else(|| {
                        carrick_syscall_abi::LinuxSiginfo::kill(
                            signal.number(),
                            carrick_syscall_abi::LINUX_SI_USER,
                            0,
                            0,
                        )
                    });
                    self.service.copy_siginfo(&mm, info, &payload)?;
                }
                return Ok(returned(i64::from(signal.number())));
            }
            if signals.has_deliverable(self.record, blocked) {
                return Ok(returned(
                    carrick_personality_linux::abi::signal::LINUX_EINTR.guest_retval(),
                ));
            }
            if let Some(deadline) = pending.deadline
                && self.service.signal_now()?.raw() >= deadline.0.raw()
            {
                return Ok(returned(
                    carrick_personality_linux::abi::signal::LINUX_EAGAIN.guest_retval(),
                ));
            }
            if self.park_signal_wait(
                pending.kind,
                pending.channel.clone(),
                observed,
                pending.deadline,
            )? {
                return Ok(LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    result: SyscallResult::new(0),
                });
            }
        }
    }
    /// The execution lane calls this before returning a woken saved syscall to
    /// userspace. It consumes the retained wait operation instead of replaying it.
    pub fn resume_pending_wait(&mut self) -> Option<LifecycleOutcome> {
        let signal_wait = self.runtime.graph.lock().signal_waits.remove(&self.record);
        if let Some(pending) = signal_wait {
            return Some(match self.resume_signal_wait(pending) {
                Ok(outcome) => outcome,
                Err(error) => self.fail(error),
            });
        }
        let pending = self.runtime.graph.lock().pending.remove(&self.key)?;
        match pending {
            PendingContinuation::Wait(pending) => {
                if pending.caller != self.key
                    || pending.channel.generation.generation() == pending.precheck.wake_generation()
                {
                    self.runtime
                        .graph
                        .lock()
                        .pending
                        .insert(self.key, PendingContinuation::Wait(pending));
                    return Some(self.fail(NativeProcessError::Stale));
                }
                Some(
                    match self.wait_query(pending.query, pending.status, false) {
                        Ok(outcome) => outcome,
                        Err(error) => self.fail(error),
                    },
                )
            }
            PendingContinuation::Ipc(pending) => Some(self.resume_ipc(pending)),
        }
    }
    fn park_continuation(
        &mut self,
        channel: &Arc<WaitChannel>,
        precheck_gen: TaskWakeGeneration,
        continuation: PendingContinuation,
    ) -> Result<ContinuationPark, NativeProcessError> {
        let zone = self.source.zone;
        let record = zone
            .slot(self.source.slot)
            .current()
            .or_else(|| zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Stale)?;
        let start = carrick_core::entry::prepare_handoff(self.binding, self.source, record)
            .ok_or(NativeProcessError::Stale)?;
        let address = WaitChannel::address(channel);
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
            &NativeBucketWait {
                lifetime: core::marker::PhantomData,
                #[cfg(test)]
                probe: self.publication_wait_probe,
            },
        );
        if channel.generation.generation() != precheck_gen {
            drop(guard);
            return Ok(ContinuationPark::Rescan);
        }
        {
            let graph = self.runtime.graph.lock();
            if graph.pending.contains_key(&self.key) {
                return Err(NativeProcessError::Busy);
            }
        }
        if self.signal_interrupts_current() {
            self.interrupted_child_wait = Some(Box::new(self.words));
            return Ok(ContinuationPark::Interrupted);
        }
        let sequence = zone.next_seq(record);
        zone.enqueue(&guard, record, sequence, channel.mm, address, u32::MAX, 0)
            .map_err(|_| NativeProcessError::Exhausted)?;
        unsafe { *zone.record(record).ctx_mut() = self.words };
        self.runtime
            .graph
            .lock()
            .pending
            .insert(self.key, continuation);
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
        Ok(ContinuationPark::Parked)
    }

    fn signal_interrupts_current(&self) -> bool {
        let graph = self.runtime.graph.lock();
        let Ok(row) = graph.owner.task(self.key) else {
            return false;
        };
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
        );
        row.native()
            .resources()
            .signals()
            .has_deliverable(self.record, blocked)
    }

    fn ipc_env(
        &self,
    ) -> Result<
        (
            carrick_personality_linux::identity::TaskCredentials,
            u32,
            Arc<SpinLock<IpcNamespace>>,
        ),
        i64,
    > {
        let graph = self.runtime.graph.lock();
        let task = graph
            .owner
            .task(self.key)
            .map_err(|_| carrick_syscall_abi::LINUX_ESRCH.guest_retval())?;
        let creds = task
            .credentials_for(self.calling_tid)
            .cloned()
            .map_err(|_| carrick_syscall_abi::LINUX_ESRCH.guest_retval())?;
        let pid = task.metadata().namespace_pid;
        let ipc = graph.ipc.clone();
        Ok((creds, pid, ipc))
    }

    fn get_or_create_channel(&self, channel_id: u64) -> Arc<WaitChannel> {
        const IPC_WAIT_CHANNEL_MM: u64 = 0x19c0_0000;
        let mut channels = self.runtime.ipc_channels.lock();
        if let Some((_, ch)) = channels.iter().find(|(id, _)| *id == channel_id) {
            ch.clone()
        } else {
            let ch = Arc::new(WaitChannel {
                generation: ProcessWake::new(),
                mm: IPC_WAIT_CHANNEL_MM,
            });
            channels.push((channel_id, ch.clone()));
            ch
        }
    }

    fn prune_ipc_channel(&self, channel_id: u64) {
        let mut channels = self.runtime.ipc_channels.lock();
        channels.retain(|(id, _)| *id != channel_id);
    }

    fn wake_ipc_channel(&mut self, channel_id: u64) {
        if channel_id == 0 {
            return;
        }
        let channel = {
            let channels = self.runtime.ipc_channels.lock();
            channels
                .iter()
                .find(|(id, _)| *id == channel_id)
                .map(|(_, ch)| ch.clone())
        };
        if let Some(channel) = channel {
            let _ = self.publish_channel(&channel);
        }
    }

    /// Reserve one timed park using the signal wait's shared counter authority.
    fn arm_park_timer(
        &mut self,
        record: carrick_sched_core::RecordId,
        sequence: u32,
        deadline: Option<carrick_guest_arch::Deadline>,
    ) -> Result<(), NativeProcessError> {
        let zone = self.source.zone;
        if deadline.is_some() && !zone.timer_admission_available(self.source.slot) {
            return Err(NativeProcessError::Busy);
        }
        zone.set_deadline(record, deadline.map_or(0, |deadline| deadline.0.raw()));
        if let Some(deadline) = deadline {
            let earliest = zone
                .timer_deadline(self.source.slot)
                .map_or(deadline.0.raw(), |owned| owned.min(deadline.0.raw()));
            self.service.arm_signal_timer(carrick_guest_arch::Deadline(
                carrick_guest_arch::CounterTick::new(earliest),
            ))?;
            zone.arm_timer(self.source.slot, record, sequence)
                .map_err(|_| NativeProcessError::Busy)?;
        }
        Ok(())
    }

    fn park_ipc(
        &mut self,
        channel: Arc<WaitChannel>,
        precheck_gen: TaskWakeGeneration,
        payload: PendingIpcPayload,
        deadline: Option<carrick_guest_arch::Deadline>,
    ) -> Result<bool, i64> {
        let ch = channel.clone();
        let zone = self.source.zone;
        let record = zone
            .slot(self.source.slot)
            .current()
            .or_else(|| zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Stale)
            .map_err(|e| e.errno())?;
        let start = carrick_core::entry::prepare_handoff(self.binding, self.source, record)
            .ok_or(NativeProcessError::Stale)
            .map_err(|e| e.errno())?;
        let address = WaitChannel::address(&ch);
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(ch.mm, address),
            &NativeBucketWait {
                lifetime: core::marker::PhantomData,
                #[cfg(test)]
                probe: self.publication_wait_probe,
            },
        );
        if ch.generation.generation() != precheck_gen {
            drop(guard);
            return Ok(false);
        }
        // Signal publication and enrollment share graph custody. A sender either
        // observes this continuation or this check observes its pending signal.
        let mut graph = self.runtime.graph.lock();
        let row = graph
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale.errno())?;
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
        );
        if row
            .native()
            .resources()
            .signals()
            .has_deliverable(self.record, blocked)
        {
            return Err(carrick_syscall_abi::LINUX_EINTR.guest_retval());
        }
        if graph.pending.contains_key(&self.key) {
            return Err(NativeProcessError::Busy.errno());
        }
        let sequence = zone.next_seq(record);
        self.arm_park_timer(record, sequence, deadline)
            .map_err(|error| error.errno())?;
        zone.enqueue(&guard, record, sequence, ch.mm, address, u32::MAX, 0)
            .map_err(|_| {
                zone.cancel_timer_admission(self.record);
                NativeProcessError::Exhausted.errno()
            })?;
        unsafe { *zone.record(record).ctx_mut() = self.words };
        graph.pending.insert(
            self.key,
            PendingContinuation::Ipc(PendingIpc {
                caller: self.key,
                channel,
                precheck_gen,
                payload,
            }),
        );
        drop(graph);
        let receipt = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_el1_abi::EntryRecordGeneration(sequence),
        );
        if receipt.is_none() {
            self.runtime.graph.lock().pending.remove(&self.key);
            zone.cancel_timer_admission(self.record);
            return Err(NativeProcessError::Busy.errno());
        }
        drop(guard);
        zone.clear_current(self.source.slot);
        self.handoff = receipt;
        Ok(true)
    }

    fn resume_ipc(&mut self, pending: PendingIpc) -> LifecycleOutcome {
        let interrupted = self.signal_interrupts_current();
        let timeout_status = match &pending.payload {
            PendingIpcPayload::Semop {
                timeout_deadline: Some(dl),
                ..
            } => match self.service.signal_now() {
                Ok(now) => Ok(now.raw() >= dl.0.raw()),
                Err(error) => Err(error.errno()),
            },
            _ => Ok(false),
        };
        if interrupted || timeout_status != Ok(false) {
            if let PendingIpcPayload::Semop {
                semid,
                blocking_sem: Some((sem_num, is_zero)),
                ..
            } = &pending.payload
            {
                let _ = self.ipc_env().map(|(_, pid, ipc)| {
                    ipc.lock()
                        .semop_suspend_exit(pid, *semid, *sem_num, *is_zero)
                });
            }
            return returned(if interrupted {
                carrick_syscall_abi::LINUX_EINTR.guest_retval()
            } else {
                timeout_status
                    .err()
                    .unwrap_or_else(|| carrick_syscall_abi::LINUX_EAGAIN.guest_retval())
            });
        }

        let (_creds, pid, ipc) = match self.ipc_env() {
            Ok(env) => env,
            Err(e) => return returned(e),
        };

        match &pending.payload {
            PendingIpcPayload::Msgsnd { msqid, .. } | PendingIpcPayload::Msgrcv { msqid, .. } => {
                if !ipc.lock().is_valid_msg_queue(*msqid) {
                    return returned(carrick_syscall_abi::LINUX_EIDRM.guest_retval());
                }
            }
            PendingIpcPayload::Semop { semid, .. } => {
                if !ipc.lock().is_valid_sem_set(*semid) {
                    return returned(carrick_syscall_abi::LINUX_EIDRM.guest_retval());
                }
            }
        }

        match pending.payload {
            PendingIpcPayload::Msgsnd {
                msqid,
                mtype,
                data,
                msgflg,
            } => match self.msgsnd(msqid, mtype, &data, msgflg) {
                Ok(IpcOutcome::Returned(r)) => returned(r.raw()),
                Ok(IpcOutcome::Suspended) => LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    result: SyscallResult::new(0),
                },
                Err(e) => returned(e),
            },
            PendingIpcPayload::Msgrcv {
                msqid,
                msgp,
                msgsz,
                msgtyp,
                msgflg,
            } => match self.msgrcv(msqid, msgp, msgtyp, msgflg, msgsz) {
                Ok((IpcOutcome::Returned(r), Some((original_idx, mtype, data)))) => {
                    let text_va = u64::try_from(data.len())
                        .ok()
                        .and_then(|len| len.checked_add(8))
                        .and_then(|len| {
                            carrick_guest_arch::UserRange::checked(
                                msgp,
                                carrick_guest_arch::GuestLen::new(len),
                            )
                        })
                        .filter(|range| range.in_lower_half())
                        .and_then(|_| msgp.raw().checked_add(8))
                        .map(UserVa::new);
                    let (ok1, ok2) = if let Some(text_va) = text_va {
                        let mtype_bytes = mtype.to_ne_bytes();
                        let mtype_ok = unsafe {
                            crate::file::copy_to_user_guarded(
                                self.current,
                                msgp.raw() as *mut u8,
                                mtype_bytes.as_ptr(),
                                8,
                            )
                        };
                        let text_ok = mtype_ok
                            && (data.is_empty()
                                || unsafe {
                                    crate::file::copy_to_user_guarded(
                                        self.current,
                                        text_va.raw() as *mut u8,
                                        data.as_ptr(),
                                        data.len(),
                                    )
                                });
                        (mtype_ok, text_ok)
                    } else {
                        (false, false)
                    };
                    if !ok1 || !ok2 {
                        let _ = self.msgrcv_restore(msqid, original_idx, mtype, data);
                        returned(carrick_syscall_abi::LINUX_EFAULT.guest_retval())
                    } else {
                        returned(r.raw())
                    }
                }
                Ok((IpcOutcome::Returned(r), None)) => returned(r.raw()),
                Ok((IpcOutcome::Suspended, _)) => LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    result: SyscallResult::new(0),
                },
                Err(e) => returned(e),
            },
            PendingIpcPayload::Semop {
                semid,
                ops,
                timeout_deadline,
                blocking_sem,
            } => {
                if let Some((sem_num, is_zero)) = blocking_sem {
                    ipc.lock().semop_suspend_exit(pid, semid, sem_num, is_zero);
                }
                let raw_sops: Vec<carrick_personality_linux::ipc::LinuxSembuf> = ops
                    .iter()
                    .map(|&(sem_num, sem_op, sem_flg)| {
                        carrick_personality_linux::ipc::LinuxSembuf {
                            sem_num,
                            sem_op,
                            sem_flg,
                        }
                    })
                    .collect();
                match self.semop_until(semid, &raw_sops, timeout_deadline) {
                    Ok(IpcOutcome::Returned(r)) => returned(r.raw()),
                    Ok(IpcOutcome::Suspended) => LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        result: SyscallResult::new(0),
                    },
                    Err(e) => returned(e),
                }
            }
        }
    }
    /// Original context of an interrupted, unconsumed child-wait query.
    /// Only this owned operation may be restarted after a caught handler.
    pub fn take_interrupted_child_wait(&mut self) -> Option<C> {
        self.interrupted_child_wait.take().map(|words| *words)
    }
    fn publish_channel(&mut self, channel: &Arc<WaitChannel>) -> Result<(), NativeProcessError> {
        publish_signal_channel(
            self.source.zone,
            self.source.slot,
            self.service,
            channel,
            #[cfg(test)]
            self.publication_wait_probe,
        )
    }
    /// Resume owned lifecycle custody before the execution lane returns to EL0.
    /// Exit keeps its original status and cannot become a guest syscall return.
    pub fn resume_pending_lifecycle(&mut self) -> Option<LifecycleOutcome> {
        let status = self
            .runtime
            .graph
            .lock()
            .pending_exit
            .get(&self.key)
            .filter(|pending| core::ptr::eq(pending.caller.control(), self.control))
            .map(|p| (p.status, p.entry));
        if let Some((status, entry)) = status {
            // SAFETY: this exact record is selected by the execution owner;
            // the same checkpoint serves in-zone and host re-entry.
            unsafe {
                self.source
                    .zone
                    .record(self.record.id)
                    .consume_owner_continuation();
            }
            return Some(match self.exit_with_status(status, entry) {
                Ok(outcome) => outcome,
                Err(error) => self.run_failed(error.run_failure_reason()),
            });
        }
        if matches!(
            self.source.zone.record(self.record.id).resume_disposition(),
            carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(_)
        ) {
            // SAFETY: this exact record is selected by the execution owner;
            // a losing exit_group caller retires its record instead of
            // returning to EL0.
            unsafe {
                self.source
                    .zone
                    .record(self.record.id)
                    .consume_owner_continuation();
            }
            self.retire_thread_identity(self.calling_tid);
            let Some(receipt) =
                carrick_core::entry::retire_current(self.binding, self.source, self.record.id)
            else {
                return Some(self.run_failed(NativeProcessError::Quarantined.run_failure_reason()));
            };
            self.handoff = Some(receipt);
            return Some(LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                result: SyscallResult::new(0),
            });
        }
        self.resume_pending_wait()
    }

    /// The ISA execution lane's single checkpoint after selecting a parked
    /// record. The owner consumes its continuation before any EL0 return.
    #[inline(never)]
    pub fn resume_checkpoint(
        &mut self,
    ) -> Result<NativeResume, carrick_core_abi::NativeRunFailureReason> {
        // CLONE_CHILD_SETTID is an effect in the child's MM. The selected
        // record now owns that MM, and no EL0 instruction has resumed yet.
        let pending = {
            let graph = self.runtime.graph.lock();
            let resources = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale.run_failure_reason())?
                .native()
                .resources();
            resources
                .pending_child_tid
                .map(|address| (resources.mm.clone(), address))
        };
        if let Some((mm, address)) = pending {
            // Linux ignores a fault while storing CLONE_CHILD_SETTID in the
            // child. Busy/Stale are copy admission refusals at this checkpoint,
            // never a reason to terminate the carrier or repeat the store.
            match self
                .service
                .copy_signal_bytes(&mm, address, &self.calling_tid.to_ne_bytes())
            {
                Ok(())
                | Err(
                    NativeProcessError::Fault
                    | NativeProcessError::Busy
                    | NativeProcessError::Stale,
                ) => {}
                Err(error) => return Err(error.run_failure_reason()),
            }
            self.runtime
                .graph
                .lock()
                .owner
                .task_mut(self.key)
                .map_err(|_| NativeProcessError::Stale.run_failure_reason())?
                .native_mut()
                .resources_mut()
                .pending_child_tid = None;
        }
        let outcome = self.resume_pending_lifecycle();
        if let Some(reason) = self.take_run_failure() {
            return Err(reason);
        }
        match outcome {
            None => Ok(NativeResume::NoPending),
            Some(LifecycleOutcome::Returned { result, .. }) => Ok(NativeResume::Returned(result)),
            Some(LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }) => {
                if self.take_handoff_receipt().is_none() {
                    return Ok(NativeResume::Invalid);
                }
                Ok(NativeResume::Left(self.take_root_exit()))
            }
            Some(_) => Ok(NativeResume::Invalid),
        }
    }

    fn park_pending_exit(
        &mut self,
        page: &ThreadLifecyclePage,
        channel: &Arc<WaitChannel>,
        entry: OwnerEntry,
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
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(channel.mm, address),
            &NativeBucketWait {
                lifetime: core::marker::PhantomData,
                #[cfg(test)]
                probe: self.publication_wait_probe,
            },
        );
        // Settlement publishes under this same bucket. A claim which settled
        // before enrollment needs no wake; a later settlement owns our wake.
        let (is_owner, ready) = {
            let graph = self.runtime.graph.lock();
            let pending = graph.pending_exit.get(&self.key);
            let is_owner = pending
                .is_some_and(|pending| core::ptr::eq(pending.caller.control(), self.control));
            let ready = pending.is_some_and(|pending| {
                pending.custody.as_ref().is_some_and(|custody| {
                    pending
                        .completed_receipts(page)
                        .is_some_and(|receipts| custody.can_settle(page, &receipts))
                })
            });
            (is_owner, ready)
        };
        if ready {
            if is_owner {
                return Ok(None);
            }
            drop(guard);
            self.retire_thread_identity(self.calling_tid);
            let receipt = carrick_core::entry::retire_current(self.binding, self.source, record)
                .ok_or(NativeProcessError::Quarantined)?;
            self.handoff = Some(receipt);
            return Ok(Some(LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                result: SyscallResult::new(0),
            }));
        }
        let sequence = zone.next_seq(record);
        zone.enqueue(&guard, record, sequence, channel.mm, address, u32::MAX, 0)
            .map_err(|_| NativeProcessError::Quarantined)?;
        // SAFETY: the current record remains owned until its guarded park CAS.
        unsafe {
            *zone.record(record).ctx_mut() = self.words;
            zone.record(record).publish_owner_continuation(entry);
        }
        let Some(receipt) = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_el1_abi::EntryRecordGeneration(sequence),
        ) else {
            if !is_owner {
                // SAFETY: the park CAS was refused while this slot still owns
                // `record`; consume the continuation and retire the losing
                // exit_group caller's record.
                unsafe {
                    zone.record(record).consume_owner_continuation();
                }
                drop(guard);
                self.retire_thread_identity(self.calling_tid);
                let receipt =
                    carrick_core::entry::retire_current(self.binding, self.source, record)
                        .ok_or(NativeProcessError::Quarantined)?;
                self.handoff = Some(receipt);
                return Ok(Some(LifecycleOutcome::Transferred {
                    progress: carrick_core::Served::Idle,
                    result: SyscallResult::new(0),
                }));
            }
            return Err(NativeProcessError::Quarantined);
        };
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
        self.exit_with_status(LinuxWaitStatus::exited(status), OwnerEntry::Syscall)
    }
    pub fn exit_with_signal(&mut self, sig: u8) -> Result<LifecycleOutcome, NativeProcessError> {
        if self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?
            .native()
            .resources()
            .page
            .live()
            != 1
        {
            return Err(NativeProcessError::GroupExitCustody);
        }
        let wait_status = LinuxWaitStatus::signaled(sig, false);
        self.exit_with_status(wait_status, OwnerEntry::Exception)
    }
    #[inline(never)]
    fn begin_closing(
        &mut self,
        wait_status: LinuxWaitStatus,
        entry: OwnerEntry,
    ) -> Result<(&'a ThreadLifecyclePage, Arc<WaitChannel>), NativeProcessError> {
        let registry = *self.runtime.registry.lock();
        let address = self
            .runtime
            .task_binding(self.key)
            .ok_or(NativeProcessError::Stale)?
            .address;
        // Adoption holds this lock through graph publication. Keep it while
        // closing the gate and taking the authoritative member snapshot.
        let registry_state = registry.map(|registry| registry.state.lock());
        #[cfg(test)]
        {
            let hook = self.runtime.closing_race_hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let mut adopted = Vec::new();
        let mut member_notification = None;
        let (page, channel, first_close) = {
            let mut graph = self.runtime.graph.lock();
            let first_close = !graph.pending_exit.contains_key(&self.key);
            let is_owner = first_close
                || graph
                    .pending_exit
                    .get(&self.key)
                    .is_some_and(|pending| core::ptr::eq(pending.caller.control(), self.control));
            let row = graph
                .owner
                .task_mut(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            if is_owner {
                row.select_exit_thread(self.calling_tid)
                    .map_err(|_| NativeProcessError::Stale)?;
            } else {
                row.credentials_for(self.calling_tid)
                    .map_err(|_| NativeProcessError::Stale)?;
            }
            let page = row.native().resources().page;
            if first_close {
                let admission = carrick_core::terminal::TerminalCustody::<
                    carrick_core::terminal::Process,
                    carrick_core::terminal::Live,
                >::close_admission(page);
                // Already admitted sibling retirement still needs its own
                // exact-record cancellation binding. Pre-live claims are
                // refused by thread_spawned after this terminal close.
                if page.live() == 0 {
                    return Err(NativeProcessError::Quarantined);
                }
                let channel = Arc::new(WaitChannel {
                    generation: ProcessWake::new(),
                    mm: self.binding.mm.raw(),
                });
                if let Some(state) = registry_state.as_deref() {
                    adopted = NativeProcessRegistry::adopted_members(
                        state,
                        self.runtime,
                        self.key,
                        self.binding,
                        page,
                    );
                }
                let mut outstanding = Vec::with_capacity(MEMBER_SET_CAPACITY);
                let mut pool = Vec::new();
                // The graph retains exact member controls across pool-entry
                // reap and restock. Snapshot them before the recyclable page
                // scan, including members that subsequently retire on host.
                let graph_controls: Vec<_> = graph
                    .owner
                    .task(self.key)
                    .map_err(|_| NativeProcessError::Stale)?
                    .native()
                    .resources()
                    .members
                    .iter()
                    .map(|member| (member.control.control(), member.expected_host))
                    .collect();
                for (control, expected_host) in graph_controls {
                    let Some(entry) = control.entry() else {
                        continue;
                    };
                    if self.control.entry() == Some(entry)
                        || carrick_el1_abi::Lifecycle::expected_exit_receipt(
                            page,
                            control,
                            Some(entry),
                        ) == carrick_core::lifecycle::ExpectedExitReceipt::AlreadyExited
                    {
                        continue;
                    }
                    pool.push(entry);
                    outstanding.push(OutstandingExitReceipt::Pool {
                        entry,
                        control: retain_member_control(control)?,
                        expected_host,
                    });
                }
                for index in 0..carrick_el1_abi::THREAD_POOL_ENTRIES {
                    if let Some((generation, _)) = page.state(index) {
                        let entry = carrick_el1_abi::EntryRef::new(index as u32, generation);
                        if page.pool_control_disposition(entry)
                            == carrick_core::lifecycle::PoolControlDisposition::Released
                            || self.control.entry() == Some(entry)
                            || pool.contains(&entry)
                        {
                            continue;
                        }
                        let expected_host = pool_host_identity(page, entry);
                        if page.pool_control_disposition(entry)
                            == carrick_core::lifecycle::PoolControlDisposition::Released
                        {
                            continue;
                        }
                        let expected_host = expected_host?;
                        let Some(address) =
                            page.control_address(entry).filter(|address| *address != 0)
                        else {
                            continue;
                        };
                        // SAFETY: an active exact entry pins its control
                        // allocation through Closing's member snapshot.
                        let control = unsafe { &*(address as *const ThreadControlSlot) };
                        #[cfg(test)]
                        {
                            let hook = self.runtime.pool_control_hook.lock().take();
                            if let Some(hook) = hook {
                                hook();
                            }
                        }
                        if page.pool_control_disposition(entry)
                            == carrick_core::lifecycle::PoolControlDisposition::Released
                            || control.entry() != Some(entry)
                            || carrick_el1_abi::Lifecycle::expected_exit_receipt(
                                page,
                                control,
                                Some(entry),
                            ) == carrick_core::lifecycle::ExpectedExitReceipt::AlreadyExited
                        {
                            continue;
                        }
                        let retained = match retain_member_control(control) {
                            Ok(retained) => retained,
                            Err(error) => {
                                // Retirement can win after the state/address
                                // read. A recycled incarnation is no longer
                                // part of this page snapshot.
                                if page.pool_control_disposition(entry)
                                    == carrick_core::lifecycle::PoolControlDisposition::Released
                                {
                                    continue;
                                }
                                return Err(error);
                            }
                        };
                        #[cfg(test)]
                        {
                            let hook = self.runtime.pool_retained_hook.lock().take();
                            if let Some(hook) = hook {
                                hook();
                            }
                        }
                        if page.pool_control_disposition(entry)
                            == carrick_core::lifecycle::PoolControlDisposition::Released
                            || control.entry() != Some(entry)
                            || carrick_el1_abi::Lifecycle::expected_exit_receipt(
                                page,
                                control,
                                Some(entry),
                            ) == carrick_core::lifecycle::ExpectedExitReceipt::AlreadyExited
                        {
                            continue;
                        }
                        pool.push(entry);
                        outstanding.push(OutstandingExitReceipt::Pool {
                            entry,
                            control: retained,
                            expected_host,
                        });
                    }
                }
                for (binding, control, _) in &adopted {
                    outstanding.push(OutstandingExitReceipt::Adopted {
                        binding: *binding,
                        control: retain_member_control(control)?,
                    });
                }
                for index in 0..carrick_el1_abi::THREAD_POOL_ENTRIES {
                    let Some(identity) = page.host_birth_identity(index) else {
                        continue;
                    };
                    if page.host_birth_receipt_returned(index) {
                        continue;
                    }
                    if self.control.host_birth_identity() == Some(identity) {
                        continue;
                    }
                    outstanding.push(OutstandingExitReceipt::HostBorn { identity, index });
                }
                // A fixture with no pool candidate uses the same one-shot
                // hook at the completed snapshot boundary.
                #[cfg(test)]
                {
                    let hook = self.runtime.pool_control_hook.lock().take();
                    if let Some(hook) = hook {
                        hook();
                    }
                }
                let bindings = outstanding
                    .iter()
                    .filter_map(|receipt| match receipt {
                        OutstandingExitReceipt::Pool { .. } => None,
                        OutstandingExitReceipt::Adopted { binding, .. } => Some(
                            carrick_core::terminal::HostThreadRetirementReceipt::from_binding(
                                *binding,
                            ),
                        ),
                        OutstandingExitReceipt::HostBorn { identity, .. } => Some(*identity),
                    })
                    .collect();
                // Every fallible retain precedes consumption. A refusal
                // drops preparation with admission still closed and no begun
                // claim or caller live unit consumed.
                let caller = retain_member_control(self.control)?;
                let custody = carrick_core::terminal::TerminalCustody::<
                    carrick_core::terminal::Process,
                    carrick_core::terminal::Live,
                >::begin_exit(
                    admission,
                    self.key,
                    address,
                    wait_status.to_termination_status(),
                )
                .map_err(|_| NativeProcessError::Quarantined)?;
                let carrick_core::terminal::RetirementVerdict::CancelMembers { members, .. } =
                    custody.cancel_members(pool, bindings)
                else {
                    unreachable!("process closing always cancels members")
                };
                for receipt in &outstanding {
                    match receipt {
                        OutstandingExitReceipt::Pool { control, .. }
                        | OutstandingExitReceipt::Adopted { control, .. } => {
                            control.commit_registration();
                        }
                        OutstandingExitReceipt::HostBorn { .. } => {}
                    }
                }
                page.publish_exit_wait(self.binding.mm, WaitChannel::address(&channel));
                let wake = Some(ExitWakeCustody {
                    channel: channel.clone(),
                });
                graph.pending_exit.insert(
                    self.key,
                    PendingExit {
                        status: wait_status,
                        entry,
                        caller,
                        channel,
                        wake,
                        outstanding,
                        members,
                        custody: Some(custody),
                    },
                );
            } else if !is_owner
                && let Some(entry) = self.control.entry()
                && carrick_el1_abi::Lifecycle::expected_exit_receipt(
                    page,
                    self.control,
                    Some(entry),
                ) == carrick_core::lifecycle::ExpectedExitReceipt::Pool
            {
                let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
                    self.binding,
                    Some(entry),
                    wait_status.to_termination_status(),
                )
                .ok_or(NativeProcessError::Quarantined)?;
                let custody = carrick_core::terminal::TerminalCustody::<
                    carrick_core::terminal::Thread,
                    carrick_core::terminal::Live,
                >::admitted(identity)
                .begin();
                let (custody, membership) = custody
                    .reserve_nonfinal(page)
                    .map_err(|_| NativeProcessError::Quarantined)?;
                let _ = page.publish(entry);
                let host_receipt = member_host_identity(page, self.control, self.binding)?;
                page.retire_published_host_member(entry, self.control, membership)
                    .map_err(|_| NativeProcessError::Quarantined)?;
                page.publish_exact_host_retirement(self.control, host_receipt);
                if let carrick_core::terminal::RetirementVerdict::RetireThread {
                    notification,
                    ..
                } = custody.into_verdict(page)
                {
                    member_notification = notification;
                }
            }
            (
                page,
                graph
                    .pending_exit
                    .get(&self.key)
                    .ok_or(NativeProcessError::Quarantined)?
                    .channel
                    .clone(),
                first_close,
            )
        };
        drop(registry_state);
        #[cfg(test)]
        if first_close {
            let hook = self.runtime.closing_race_hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        if first_close && let Some(registry) = registry {
            let members = self
                .runtime
                .graph
                .lock()
                .pending_exit
                .get(&self.key)
                .ok_or(NativeProcessError::Quarantined)?
                .members
                .clone();
            registry.cancel_members(self.runtime, page, &members, &adopted);
        }
        if let Some(notification) = member_notification {
            let service = &mut self.service;
            publish_terminal_notification(
                &notification,
                self.source.zone,
                self.source.slot,
                &NativeBucketWait {
                    lifetime: core::marker::PhantomData,
                    #[cfg(test)]
                    probe: self.publication_wait_probe,
                },
                |channel| service.wake_unplaceable_wait(channel),
            )
            .map_err(|_| NativeProcessError::Quarantined)?;
        }
        Ok((page, channel))
    }

    #[inline(never)]
    fn exit_with_status(
        &mut self,
        wait_status: LinuxWaitStatus,
        entry: OwnerEntry,
    ) -> Result<LifecycleOutcome, NativeProcessError> {
        let child_pid = self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .map_err(|_| NativeProcessError::Stale)?
            .metadata()
            .namespace_pid;
        let root_exit = self.is_root_process();
        let (page, channel) = self.begin_closing(wait_status, entry)?;
        let settled = loop {
            if let Some(outcome) = self.park_pending_exit(page, &channel, entry)? {
                return Ok(outcome);
            }
            #[cfg(test)]
            {
                let hook = self.runtime.settle_race_hook.lock().take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            let attempt = {
                let mut graph = self.runtime.graph.lock();
                let pending = graph
                    .pending_exit
                    .get_mut(&self.key)
                    .ok_or(NativeProcessError::Quarantined)?;
                let receipts = pending.completed_receipts(page);
                let custody = pending
                    .custody
                    .take()
                    .ok_or(NativeProcessError::Quarantined)?;
                let result = match receipts {
                    Some(receipts) => custody.settle(page, receipts),
                    None => Err(custody),
                };
                match result {
                    Ok(settled) => Some(settled),
                    Err(closing) => {
                        pending.custody = Some(closing);
                        None
                    }
                }
            };
            if let Some(settled) = attempt {
                break settled;
            }
            // A host retirement can claim its birth slot after the ready
            // check. Re-enrol on the channel and recheck under its lock.
        };
        let _identity = settled.identity();
        let clear_child_tid = self.control.clear_child_tid();
        if clear_child_tid != 0 {
            let mm = self
                .runtime
                .graph
                .lock()
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
                .native()
                .resources()
                .mm
                .clone();
            if self
                .service
                .copy_signal_bytes(&mm, UserVa::new(clear_child_tid), &0_u32.to_ne_bytes())
                .is_ok()
            {
                let zone = self.source.zone;
                let guard = zone.short_lock(
                    ZoneTables::<C>::bucket_of_with_context(self.binding.mm.raw(), clear_child_tid),
                    &NativeBucketWait {
                        lifetime: core::marker::PhantomData,
                        #[cfg(test)]
                        probe: self.publication_wait_probe,
                    },
                );
                let mut effects = WakeEffects::default();
                let wake = zone.wake_placed(
                    &guard,
                    self.binding.mm.raw(),
                    clear_child_tid,
                    carrick_personality_linux::thread::CHILD_TID_WAKE_MASK,
                    carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
                    carrick_sched_core::Waker::El1 {
                        slot: self.source.slot,
                    },
                    &mut [],
                    &mut effects,
                );
                drop(guard);
                if matches!(wake, Err(carrick_sched_core::WakeRefusal::Unplaceable)) {
                    self.service.wake_unplaceable_wait(ProcessWaitChannel {
                        mm: self.binding.mm,
                        address: core::num::NonZeroU64::new(clear_child_tid)
                            .ok_or(NativeProcessError::Quarantined)?,
                    })?;
                } else {
                    wake.map_err(|_| NativeProcessError::Quarantined)?;
                    self.service.wake_effects(effects);
                }
                self.control.set_clear_child_tid(0);
            }
        }
        let transaction = self
            .runtime
            .graph
            .lock()
            .serials
            .allocate()
            .ok_or(NativeProcessError::Exhausted)?;
        let pid = self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .ok()
            .map(|t| t.metadata().namespace_pid);
        let _ = self.runtime.graph.lock().pending.remove(&self.key);
        if let Some(pid) = pid {
            let ipc = self.runtime.graph.lock().ipc.clone();
            let channels = ipc.lock().exit_process(pid);
            for ch in channels {
                self.wake_ipc_channel(ch);
            }
        }
        let (page, file_table, resources, published) = {
            let mut graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task_mut(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
            row.select_exit_thread(self.calling_tid)
                .map_err(|_| NativeProcessError::Stale)?;
            let page = row.native().resources().page;
            let file_table = row.native().resources().file_table;
            let (resources, published) = match native_process_entry::publish_exit(
                &mut graph.owner,
                self.key,
                None,
                transaction,
                wait_status,
                || {
                    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
                    crate::isa::aarch64::check_process_stack(self.source.slot);
                },
            ) {
                Ok(published) => published,
                Err(_) => return Err(NativeProcessError::Quarantined),
            };
            graph.pending_exit.remove(&self.key);
            (page, file_table, resources, published)
        };
        let record = self
            .source
            .zone
            .slot(self.source.slot)
            .current()
            .or_else(|| self.source.zone.slot(self.source.slot).host_record())
            .ok_or(NativeProcessError::Quarantined)?;
        self.handoff = carrick_core::entry::retire_current(self.binding, self.source, record);
        if self.handoff.is_none() {
            return Err(NativeProcessError::Quarantined);
        }
        if let Some(entry) = self.control.entry() {
            page.retire_closing_caller(entry)
                .map_err(|_| NativeProcessError::Quarantined)?;
        }
        page.clear_exit_wait();
        let permit = published.effects.cancel_members(|member| {
            if member.zone.live(member.record).is_some() {
                let _ = member.zone.claim_for_host(
                    member.record,
                    None,
                    Handback::Cancelled,
                    &NativeBucketWait {
                        lifetime: core::marker::PhantomData,
                        #[cfg(test)]
                        probe: self.publication_wait_probe,
                    },
                );
            }
        });
        // Graph removal (`publish_exit`) and member cancellation are complete.
        // Unregister from `NativeProcessRegistry` and release all
        // `MemberControlCustody` references (graph resources, registry member,
        // and this entry) BEFORE `retire_mm` quarantines the child's fork stock
        // and publishes slot absence (`leave_space`). Once slot absence is
        // published, a concurrent `fork()` on another CPU can reclaim and zero
        // or re-loan this child's `ThreadControlSlot` storage
        // (`window.clear(lifecycle)`), so a later `MemberControlCustody::drop`
        // (`fetch_sub(GRAPH_REFERENCE)`) would dirty the zeroed stock window
        // or underflow the next child's control word into `RESETTING`.
        if let Some(registry) = *self.runtime.registry.lock() {
            registry.unregister_process(self.runtime, self.key);
        }
        drop(published.retiring);
        drop(self._control_custody.take());
        // Only fork-born processes own stock to retire. The root is known by
        // graph position, not by the pid it shows in its namespace (a child
        // in a new PID namespace may show pid 1); it uses the root-exit
        // crossing instead. The MM is retired (stock quarantined, slot
        // absence published) before the parent is signalled or its wait
        // woken, as Linux releases the mm in exit_mm before exit_notify:
        // a parent that forks again as soon as its wait returns must find
        // this child's stock reclaimable, not still charged to a live MM.
        if let Some(mm) = resources
            && !root_exit
        {
            self.service.retire_mm(mm);
        }
        self.service.retire_fd_table(file_table);
        // A parent may scan without waiting for our notification. Publish
        // status readiness only after the child stock and slot absence are
        // retired, so that scan cannot admit a fork against charged stock.
        #[cfg(test)]
        if let Some(probe) = self.exit_notification_probe {
            probe();
        }
        let (channels, autoreaped_receipt, notified) = {
            let mut graph = self.runtime.graph.lock();
            // Keep readiness and current-parent selection in one graph
            // projection: an adopter parked on this pending receipt owns
            // the completion wake even if the original parent has exited.
            // Resolve the owned receipt at delivery, not before dropping custody.
            // Native signal locks are leaves in the graph -> signal lock order
            // (also used by fork admission and autoreap policy). Enqueue has no
            // graph or scheduler callback. Keep selection through enqueue and
            // channel capture atomic with respect to exact-generation reparenting;
            // only the scheduler wake runs after releasing graph custody.
            // Select the parent and capture channels before automatic removal
            // drops the receipt and parent edge; publish readiness before the
            // signal is enqueued.
            let parent = graph.owner.exit_notification_parent(&permit);
            let target = graph.owner.select_exit_parent(&permit);
            let mut channels = Vec::new();
            for key in [parent, published.adopter].into_iter().flatten() {
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
            let autoreaped_receipt = graph.owner.publish_exit_retirement(published.retirement);
            // Hold a delivery failure until the guard is released: automatic
            // removal custody is disposed outside graph custody on every path.
            let notified = target.map_or(Ok(()), |target| {
                let notification = target.prepare();
                let Some(signal) = notification.signal else {
                    return Ok(());
                };
                let signals = graph
                    .owner
                    .task(notification.parent)
                    .map_err(|_| NativeProcessError::Stale)?
                    .native()
                    .resources()
                    .signals
                    .clone();
                let signal = carrick_signal_core::policy::Signal::from_number(signal.raw())
                    .ok_or(NativeProcessError::Invalid)?;
                let (code, status) = if let Some(term) = wait_status.term_signal() {
                    (
                        if wait_status.raw() & 0x80 != 0 {
                            carrick_syscall_abi::LINUX_CLD_DUMPED
                        } else {
                            carrick_syscall_abi::LINUX_CLD_KILLED
                        },
                        i32::from(term),
                    )
                } else {
                    (
                        carrick_syscall_abi::LINUX_CLD_EXITED,
                        (wait_status.raw() >> 8) & 0xff,
                    )
                };
                let info = carrick_syscall_abi::LinuxSiginfo::child_exit(
                    signal.number(),
                    child_pid as i32,
                    0,
                    code,
                    status,
                );
                signals
                    .enqueue(notification.parent, signal, Some(info))
                    .map(|_| ())
                    .map_err(|_| NativeProcessError::Stale)
            });
            (channels, autoreaped_receipt, notified)
        };
        notified?;
        for channel in channels {
            self.publish_channel(&channel)?;
        }
        drop(autoreaped_receipt);
        if root_exit {
            self.root_exit = Some(wait_status);
        }
        Ok(LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            result: SyscallResult::new(0),
        })
    }
    #[inline(never)]
    fn fork_owned(&mut self, child_tid: ProcessForkChildTid) -> Result<u32, NativeProcessError> {
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
                id: carrick_personality_linux::identity::task_id_from_linux_pid(number.get())
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
                            execution: carrick_core_abi::entry::EntryGeneration::from_raw(
                                child_key.serial.raw(),
                            ),
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
            if control
                .reset_for_birth(
                    blocked,
                    if child_tid.clear {
                        child_tid.address.raw()
                    } else {
                        0
                    },
                    lifecycle_entry,
                )
                .is_err()
            {
                page.unclaim(claim)
                    .map_err(|_| NativeProcessError::Quarantined)?;
                return Err(NativeProcessError::Busy);
            }
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
                        clone_flags: child_tid.flags(),
                        clear_child_tid: if child_tid.clear {
                            child_tid.address.raw()
                        } else {
                            0
                        },
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
        let retained = (|| {
            let leader = carrick_core::lifecycle::MemberControlCustody::retain(control)
                .map_err(|_| NativeProcessError::Stale)?;
            let member = retain_member_control(control)?;
            let expected = carrick_core::terminal::HostThreadRetirementReceipt::from_parts(
                carrick_core_abi::EntryTaskKey::from_raw(child_key.id.raw() as u64),
                carrick_core_abi::EntryGeneration::from_raw(child_key.serial.raw()),
                carrick_core_abi::EntryThreadGeneration::from_raw(thread_serial.get()),
            )
            .ok_or(NativeProcessError::Stale)?;
            Ok((leader, member, expected))
        })();
        let (leader_custody, member_custody, expected_host) = match retained {
            Ok(retained) => retained,
            Err(error) => {
                self.runtime.graph.lock().owner.rollback_birth(&permit);
                if let Err((_, p)) = self.service.abort_mm(prepared) {
                    self.service.quarantine_prepared(p);
                }
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
                drop(member_custody);
                drop(leader_custody);
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
            drop(member_custody);
            drop(leader_custody);
            if let Err((_, p)) = self.service.abort_mm(prepared) {
                self.service.quarantine_prepared(p)
            };
            return Err(error);
        }
        let child_words = self.service.fork_child_context(self.words, &prepared);
        // SAFETY: this exact newly allocated record remains Free and unpublished.
        unsafe { *self.source.zone.record(record).ctx_mut() = child_words };
        let member_registration = member_custody.clone();
        let resources = NativeResources {
            _control_custody: leader_custody,
            zone: self.source.zone,
            record: self.source.zone.record_ref(record),
            control,
            page,
            members: vec![NativeMember {
                thread: NativeThreadIdentity::Issued(child_key),
                process: child_key,
                zone: self.source.zone,
                record: self.source.zone.record_ref(record),
                control: member_custody,
                expected_host,
            }],
            mm: self.service.prepared_mm(&prepared),
            address,
            pending_child_tid: child_tid.set.then_some(child_tid.address),
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
        let child_task = child_key.serial.nonzero();
        let child_execution = child_key.serial.nonzero();
        let result = {
            let mut graph = self.runtime.graph.lock();
            prep.try_publish_with(&mut graph.owner, |prepared| {
                self.service
                    .commit_child(prepared, child_task, child_execution)
            })
        };
        let published = match result {
            Ok(p) => {
                member_registration.commit_registration();
                p
            }
            Err(failure) => {
                drop(member_registration);
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
        if let Some(registry) = *self.runtime.registry.lock() {
            registry
                .register_child(
                    self.runtime,
                    NativeChildRegistration {
                        parent_binding: self.binding,
                        parent_address: self.caller_address,
                        child: child_key,
                        thread_generation: thread_serial.get(),
                        address,
                        record: self.source.zone.record_ref(record),
                    },
                )
                .map_err(|_| NativeProcessError::Quarantined)?;
        }
        self.source.zone.requeue_preempted(self.source.slot, record);
        Ok(visible.get())
    }
}
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>> ProcessNative<C>
    for NativeProcessEntry<'_, 'a, M, C, S>
{
    fn resume_owned_continuation(&mut self) -> Option<LifecycleOutcome> {
        core::mem::take(&mut self.owner_continuation)
            .then(|| self.resume_pending_lifecycle())
            .flatten()
    }
    fn take_run_failure(&mut self) -> Option<carrick_core_abi::NativeRunFailureReason> {
        self.run_failure.take()
    }
    fn copy_out_owned(&mut self, dst: UserVa, bytes: &[u8]) -> Option<bool> {
        Some(self.copy_signal_frame(dst, bytes).is_ok())
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
    fn fork(&mut self, child_tid: ProcessForkChildTid) -> LifecycleOutcome {
        match self.fork_owned(child_tid) {
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
            Err(error) => self.run_failed(error.run_failure_reason()),
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
    fn as_ipc_venue(&mut self) -> Option<&mut dyn carrick_personality_linux::ipc::ProcessIpcVenue> {
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
        if !task.native().resources().page.gate().serves_ring() {
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
    fn retire_thread_verdict(&mut self, verdict: carrick_core::terminal::RetirementVerdict) {
        self.retire_thread_verdict(verdict);
    }
    fn route_host_thread_exit(
        &mut self,
        verdict: carrick_core::terminal::RetirementVerdict,
    ) -> bool {
        let carrick_core::terminal::RetirementVerdict::RetireThreadOnHost { identity } = verdict
        else {
            return false;
        };
        if identity.binding() != self.binding || identity.entry() != self.control.entry() {
            self.run_failure = Some(carrick_core_abi::NativeRunFailureReason::NativeStale);
            return false;
        }
        self.control.request_host_exit();
        true
    }
    fn lifecycle_admission_settled(&mut self) -> Result<(), i64> {
        let wake = {
            let mut graph = self.runtime.graph.lock();
            if graph.pending_exit.contains_key(&self.key) {
                let page = graph
                    .owner
                    .task(self.key)
                    .map_err(|_| NativeProcessError::Quarantined)
                    .map(|row| row.native().resources().page);
                page.map(|page| {
                    let ready = graph.pending_exit.get(&self.key).is_some_and(|pending| {
                        pending.custody.as_ref().is_some_and(|custody| {
                            pending
                                .completed_receipts(page)
                                .is_some_and(|receipts| custody.can_settle(page, &receipts))
                        })
                    });
                    if ready {
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
            self.run_failure = Some(carrick_core_abi::NativeRunFailureReason::BirthSettlement);
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
        if let Some(member) = resources
            .members
            .iter()
            .find(|member| member.control.visible_tid() == Some(tid))
        {
            return Ok(member.control.robust_list());
        }
        let entry = resources
            .page
            .entry_ref_for_visible_tid(tid)
            .ok_or(carrick_personality_linux::identity::ESRCH)?;
        read_slot(resources.page, entry).ok_or(carrick_personality_linux::identity::ESRCH)
    }
    fn signal_venue(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::signal::ProcessSignals> {
        Some(self)
    }
}

pub(super) fn publish_terminal_notification<C: carrick_el1_abi::EntryContext>(
    notification: &carrick_core::terminal::TerminalNotification,
    zone: &ZoneTables<C>,
    slot: carrick_el1_abi::SlotId,
    wait: &impl carrick_sched_core::ShortLockWait,
    wake_unplaceable: impl FnOnce(ProcessWaitChannel) -> Result<(), NativeProcessError>,
) -> Result<(), NativeProcessError> {
    match notification.publish(zone, slot, wait) {
        Ok(effects) => {
            crate::sched::object_wait::deliver_wake_effects(zone, slot, effects);
            Ok(())
        }
        Err(carrick_sched_core::WakeRefusal::Unplaceable) => wake_unplaceable(ProcessWaitChannel {
            mm: notification.mm,
            address: notification.address,
        }),
        Err(_) => Err(NativeProcessError::Quarantined),
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    #[inline(never)]
    pub fn retire_thread_verdict(&mut self, verdict: carrick_core::terminal::RetirementVerdict) {
        #[cfg(test)]
        if let Some(hook) = self.runtime.raw_exit_after_commit_hook.lock().take() {
            hook();
        }
        let carrick_core::terminal::RetirementVerdict::RetireThread {
            identity,
            requires_slot_absence,
            notification,
        } = verdict
        else {
            self.run_failure = Some(carrick_core_abi::NativeRunFailureReason::NativeStale);
            return;
        };
        if identity.binding() != self.binding
            || identity.entry() != self.control.entry()
            || !requires_slot_absence
        {
            self.run_failure = Some(carrick_core_abi::NativeRunFailureReason::NativeStale);
            return;
        }
        let Some(tid) = self.control.visible_tid() else {
            self.run_failure = Some(carrick_core_abi::NativeRunFailureReason::NativeStale);
            return;
        };
        self.retire_thread_identity(tid);
        if let Some(notification) = notification {
            let service = &mut self.service;
            if publish_terminal_notification(
                &notification,
                self.source.zone,
                self.source.slot,
                &NativeBucketWait {
                    lifetime: core::marker::PhantomData,
                    #[cfg(test)]
                    probe: self.publication_wait_probe,
                },
                |channel| service.wake_unplaceable_wait(channel),
            )
            .is_err()
            {
                self.run_failure = Some(carrick_core_abi::NativeRunFailureReason::BirthSettlement);
            }
        }
    }

    fn retire_thread_identity(&mut self, tid: u32) {
        let mut graph = self.runtime.graph.lock();
        let mut retired = Vec::new();
        if let Ok(task) = graph.owner.task_mut(self.key) {
            if tid == task.metadata().namespace_pid {
                return;
            }
            task.remove_thread(tid);
            task.native_mut().resources_mut().members.retain(|member| {
                let matches_caller = tid == self.calling_tid
                    && (member.record == self.record
                        || core::ptr::eq(member.control.control(), self.control));
                if matches_caller {
                    retired.push(member.record);
                    false
                } else {
                    true
                }
            });
        }
        drop(graph);
        if let Some(registry) = *self.runtime.registry.lock() {
            for record in retired {
                registry.unregister_member(self.runtime, self.key, record);
            }
        }
    }

    fn robust_target<'g>(
        &self,
        owner: &'g Owner<'a, M, C>,
        tid: u32,
    ) -> Result<&'g NativeIdentityTask<'a, M, C>, i64> {
        use carrick_personality_linux::identity::{EPERM, ESRCH, LinuxCapabilitySet};
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
        f: &mut dyn FnMut(
            &mut carrick_personality_linux::identity::TaskCredentials,
        ) -> Result<(), i64>,
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
                .map(carrick_personality_linux::identity::TaskGid::new)
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
            .namespace_key(self.key, target_tid)
            .ok()
            .flatten()
            .and_then(|key| graph.owner.task(key).ok())
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
            .namespace_key(self.key, pid as u32)
            .ok()
            .flatten()
            .and_then(|key| graph.owner.task(key).ok())
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
                .namespace_key(self.key, target_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task(key).ok())
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
                    .namespace_key(self.key, target_pid)
                    .ok()
                    .flatten()
                    .and_then(|key| graph.owner.task(key).ok())
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
                .namespace_key(self.key, target_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
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
            .namespace_key(self.key, pid as u32)
            .ok()
            .flatten()
            .and_then(|key| graph.owner.task(key).ok())
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
                .namespace_key(self.key, target_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task(key).ok())
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
                .namespace_key(self.key, target_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
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

impl<'r, 'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    carrick_personality_linux::ipc::ProcessIpcVenue for NativeProcessEntry<'r, 'a, M, C, S>
{
    fn msgget(&mut self, key: i32, msgflg: i32) -> Result<i32, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .msgget(&creds, key, msgflg)
            .map_err(|e| e.guest_retval())
    }

    fn msgctl(&mut self, msqid: i32, cmd: i32, buf: Option<&mut LinuxMsqidDs>) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        match cmd {
            carrick_personality_linux::ipc::IPC_RMID => {
                let ch_id = ipc
                    .lock()
                    .msgctl_rmid(&creds, msqid)
                    .map_err(|e| e.guest_retval())?;
                self.wake_ipc_channel(ch_id);
                self.prune_ipc_channel(ch_id);
                Ok(0)
            }
            carrick_personality_linux::ipc::IPC_STAT | carrick_personality_linux::ipc::MSG_STAT => {
                let ds = buf.ok_or(carrick_syscall_abi::LINUX_EFAULT.guest_retval())?;
                ipc.lock()
                    .msgctl_stat(&creds, msqid, cmd, ds)
                    .map_err(|e| e.guest_retval())
            }
            carrick_personality_linux::ipc::IPC_SET => {
                let ds = buf.ok_or(carrick_syscall_abi::LINUX_EFAULT.guest_retval())?;
                let (raised, channel) = ipc
                    .lock()
                    .msgctl_set(&creds, msqid, ds)
                    .map_err(|e| e.guest_retval())?;
                if raised {
                    self.wake_ipc_channel(channel);
                }
                Ok(0)
            }
            _ => Err(carrick_syscall_abi::LINUX_EINVAL.guest_retval()),
        }
    }

    fn msgctl_info(&mut self, _cmd: i32, buf: &mut LinuxMsginfo) -> Result<i64, i64> {
        let (_, _, ipc) = self.ipc_env()?;
        ipc.lock().msgctl_info(buf).map_err(|e| e.guest_retval())
    }

    fn msgsnd(
        &mut self,
        msqid: i32,
        mtype: i64,
        mtext: &[u8],
        msgflg: i32,
    ) -> Result<IpcOutcome, i64> {
        let (creds, pid, ipc) = self.ipc_env()?;
        let mut has_suspended = false;
        loop {
            let ch_id = {
                let ipc_guard = ipc.lock();
                let queue = ipc_guard.msg_queue(msqid).map_err(|e| {
                    if has_suspended && matches!(e, IpcError::InvalidArgument) {
                        carrick_syscall_abi::LINUX_EIDRM.guest_retval()
                    } else {
                        e.guest_retval()
                    }
                })?;
                queue.wait_channel
            };
            let channel = self.get_or_create_channel(ch_id);
            let precheck_gen = channel.generation.generation();
            let (outcome, ch_to_wake) = {
                let mut ipc_guard = ipc.lock();
                ipc_guard
                    .msgsnd(&creds, pid, msqid, mtype, mtext, msgflg)
                    .map_err(|e| {
                        if has_suspended && matches!(e, IpcError::InvalidArgument) {
                            carrick_syscall_abi::LINUX_EIDRM.guest_retval()
                        } else {
                            e.guest_retval()
                        }
                    })?
            };
            match outcome {
                MsgsndOutcome::Complete => {
                    self.wake_ipc_channel(ch_to_wake);
                    return Ok(IpcOutcome::Returned(SyscallResult::new(0)));
                }
                MsgsndOutcome::Suspend => {
                    has_suspended = true;
                    let payload = PendingIpcPayload::Msgsnd {
                        msqid,
                        mtype,
                        data: mtext.to_vec(),
                        msgflg,
                    };
                    if !self.park_ipc(channel, precheck_gen, payload, None)? {
                        continue;
                    }
                    return Ok(IpcOutcome::Suspended);
                }
            }
        }
    }

    fn msgrcv(
        &mut self,
        msqid: i32,
        msgp: UserVa,
        msgtyp: i64,
        msgflg: i32,
        msgsz: usize,
    ) -> MsgrcvResult {
        let (creds, pid, ipc) = self.ipc_env()?;
        let mut has_suspended = false;
        loop {
            let ch_id = {
                let ipc_guard = ipc.lock();
                let queue = ipc_guard.msg_queue(msqid).map_err(|e| {
                    if has_suspended && matches!(e, IpcError::InvalidArgument) {
                        carrick_syscall_abi::LINUX_EIDRM.guest_retval()
                    } else {
                        e.guest_retval()
                    }
                })?;
                queue.wait_channel
            };
            let channel = self.get_or_create_channel(ch_id);
            let precheck_gen = channel.generation.generation();
            let (outcome, ch_to_wake) = {
                let mut ipc_guard = ipc.lock();
                ipc_guard
                    .msgrcv(&creds, pid, msqid, msgsz, msgtyp, msgflg)
                    .map_err(|e| {
                        if has_suspended && matches!(e, IpcError::InvalidArgument) {
                            carrick_syscall_abi::LINUX_EIDRM.guest_retval()
                        } else {
                            e.guest_retval()
                        }
                    })?
            };
            match outcome {
                MsgrcvOutcome::Complete { msg, original_idx } => {
                    self.wake_ipc_channel(ch_to_wake);
                    let len = msg.data.len();
                    return Ok((
                        IpcOutcome::Returned(SyscallResult::new(len as i64)),
                        Some((original_idx, msg.mtype, msg.data)),
                    ));
                }
                MsgrcvOutcome::Suspend => {
                    has_suspended = true;
                    let payload = PendingIpcPayload::Msgrcv {
                        msqid,
                        msgp,
                        msgsz,
                        msgtyp,
                        msgflg,
                    };
                    if !self.park_ipc(channel, precheck_gen, payload, None)? {
                        continue;
                    }
                    return Ok((IpcOutcome::Suspended, None));
                }
            }
        }
    }

    fn msgrcv_restore(
        &mut self,
        msqid: i32,
        original_idx: usize,
        mtype: i64,
        data: Vec<u8>,
    ) -> Result<(), i64> {
        let (_, _, ipc) = self.ipc_env()?;
        let ch = ipc
            .lock()
            .msgrcv_restore(msqid, original_idx, mtype, data)
            .map_err(|e| e.guest_retval())?;
        self.wake_ipc_channel(ch);
        Ok(())
    }

    fn semget(&mut self, key: i32, nsems: i32, semflg: i32) -> Result<i32, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semget(&creds, key, nsems, semflg)
            .map_err(|e| e.guest_retval())
    }

    fn sem_nsems(&mut self, semid: i32) -> Result<usize, i64> {
        let (_, _, ipc) = self.ipc_env()?;
        let ipc = ipc.lock();
        let set = ipc.sem_set(semid).map_err(|e| e.guest_retval())?;
        Ok(set.sems.len())
    }

    fn semctl_rmid(&mut self, semid: i32) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        let ch = ipc
            .lock()
            .semctl_rmid(&creds, semid)
            .map_err(|e| e.guest_retval())?;
        self.wake_ipc_channel(ch);
        self.prune_ipc_channel(ch);
        Ok(0)
    }

    fn semctl_stat(
        &mut self,
        semid: i32,
        _semnum: i32,
        cmd: i32,
        ds: &mut LinuxSemidDs,
    ) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_stat(&creds, semid, cmd, ds)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_set(&mut self, semid: i32, ds: &LinuxSemidDs) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_set(&creds, semid, ds)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_info(&mut self, _cmd: i32, info: &mut LinuxSeminfo) -> Result<i64, i64> {
        let (_, _, ipc) = self.ipc_env()?;
        ipc.lock().semctl_info(info).map_err(|e| e.guest_retval())
    }

    fn semctl_getval(&mut self, semid: i32, semnum: i32) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_getval(&creds, semid, semnum)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_setval(&mut self, semid: i32, semnum: i32, val: u64) -> Result<i64, i64> {
        let (creds, pid, ipc) = self.ipc_env()?;
        let ch = ipc
            .lock()
            .semctl_setval(&creds, pid, semid, semnum, val)
            .map_err(|e| e.guest_retval())?;
        self.wake_ipc_channel(ch);
        Ok(0)
    }

    fn semctl_getpid(&mut self, semid: i32, semnum: i32) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_getpid(&creds, semid, semnum)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_getncnt(&mut self, semid: i32, semnum: i32) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_getncnt(&creds, semid, semnum)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_getzcnt(&mut self, semid: i32, semnum: i32) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_getzcnt(&creds, semid, semnum)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_getall(&mut self, semid: i32, out: &mut [u16]) -> Result<i64, i64> {
        let (creds, _, ipc) = self.ipc_env()?;
        ipc.lock()
            .semctl_getall(&creds, semid, out)
            .map_err(|e| e.guest_retval())
    }

    fn semctl_setall(&mut self, semid: i32, vals: &[u16]) -> Result<i64, i64> {
        let (creds, pid, ipc) = self.ipc_env()?;
        let ch = ipc
            .lock()
            .semctl_setall(&creds, pid, semid, vals)
            .map_err(|e| e.guest_retval())?;
        self.wake_ipc_channel(ch);
        Ok(0)
    }

    fn semop(
        &mut self,
        semid: i32,
        sops: &[LinuxSembuf],
        timeout: Option<Duration>,
    ) -> Result<IpcOutcome, i64> {
        let deadline = timeout
            .map(|duration| {
                self.service
                    .signal_deadline(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
                    .map_err(|error| error.errno())
            })
            .transpose()?;
        self.semop_until(semid, sops, deadline)
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    fn semop_until(
        &mut self,
        semid: i32,
        sops: &[LinuxSembuf],
        deadline: Option<carrick_guest_arch::Deadline>,
    ) -> Result<IpcOutcome, i64> {
        let (creds, pid, ipc) = self.ipc_env()?;
        let raw_sops: Vec<(u16, i16, i16)> = sops
            .iter()
            .map(|s| (s.sem_num, s.sem_op, s.sem_flg))
            .collect();
        let mut prev_blocking: Option<(u16, bool)> = None;
        let mut has_suspended = false;
        loop {
            let ch_id = {
                let mut ipc_guard = ipc.lock();
                if let Some((num, is_zero)) = prev_blocking.take() {
                    ipc_guard.semop_suspend_exit(pid, semid, num, is_zero);
                }
                let set = ipc_guard.sem_set(semid).map_err(|e| {
                    if has_suspended && matches!(e, IpcError::InvalidArgument) {
                        carrick_syscall_abi::LINUX_EIDRM.guest_retval()
                    } else {
                        e.guest_retval()
                    }
                })?;
                set.wait_channel
            };
            let channel = self.get_or_create_channel(ch_id);
            let precheck_gen = channel.generation.generation();
            let (outcome, ch_to_wake) = {
                let mut ipc_guard = ipc.lock();
                let (outcome, ch_to_wake) = ipc_guard
                    .semop(&creds, pid, semid, &raw_sops)
                    .map_err(|e| {
                        if has_suspended && matches!(e, IpcError::InvalidArgument) {
                            carrick_syscall_abi::LINUX_EIDRM.guest_retval()
                        } else {
                            e.guest_retval()
                        }
                    })?;
                if let SemopOutcome::Suspend { sem_num, is_zero } = outcome {
                    ipc_guard.semop_suspend_enter(pid, semid, sem_num, is_zero);
                }
                (outcome, ch_to_wake)
            };
            match outcome {
                SemopOutcome::Complete => {
                    self.wake_ipc_channel(ch_to_wake);
                    return Ok(IpcOutcome::Returned(SyscallResult::new(0)));
                }
                SemopOutcome::Suspend { sem_num, is_zero } => {
                    has_suspended = true;
                    if let Some(dl) = deadline {
                        let now = match self.service.signal_now() {
                            Ok(now) => now,
                            Err(error) => {
                                ipc.lock().semop_suspend_exit(pid, semid, sem_num, is_zero);
                                return Err(error.errno());
                            }
                        };
                        if now.raw() >= dl.0.raw() {
                            ipc.lock().semop_suspend_exit(pid, semid, sem_num, is_zero);
                            return Err(carrick_syscall_abi::LINUX_EAGAIN.guest_retval());
                        }
                    }
                    prev_blocking = Some((sem_num, is_zero));
                    let payload = PendingIpcPayload::Semop {
                        semid,
                        ops: raw_sops.clone(),
                        timeout_deadline: deadline,
                        blocking_sem: Some((sem_num, is_zero)),
                    };
                    match self.park_ipc(channel, precheck_gen, payload, deadline) {
                        Ok(true) => return Ok(IpcOutcome::Suspended),
                        Ok(false) => continue,
                        Err(e) => {
                            ipc.lock().semop_suspend_exit(pid, semid, sem_num, is_zero);
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    carrick_personality_linux::signal::ProcessSignals for NativeProcessEntry<'_, 'a, M, C, S>
{
    fn force_sigsegv(
        &mut self,
        blocked: carrick_signal_core::policy::SigBlockMask,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        self.force_sigsegv_info(
            blocked,
            carrick_syscall_abi::LinuxSiginfo::kernel(
                carrick_signal_core::policy::Signal::SEGV.number(),
            ),
        )
    }
    fn rt_sigaction(
        &mut self,
        signal: carrick_signal_core::policy::Signal,
        act: Option<carrick_signal_core::policy::Action>,
    ) -> Result<carrick_signal_core::policy::Action, carrick_syscall_abi::LinuxErrno> {
        let einval = carrick_personality_linux::abi::signal::LINUX_EINVAL;
        let esrch = carrick_personality_linux::abi::signal::LINUX_ESRCH;
        let graph = self.runtime.graph.lock();
        let row = graph.owner.task(self.key).map_err(|_| esrch)?;
        let resources = row.native().resources();
        let signals = resources.signals();
        if let Some(new_action) = act {
            let old = signals
                .install_action(self.key, signal, new_action)
                .map_err(|_| einval)?;
            resources.sync_non_interrupting_signals();
            Ok(old)
        } else {
            Ok(signals.action(signal))
        }
    }

    fn rt_sigpending(&self, blocked: carrick_signal_core::policy::SigBlockMask) -> u64 {
        let graph = self.runtime.graph.lock();
        let Ok(row) = graph.owner.task(self.key) else {
            return 0;
        };
        let pending = row.native().resources().signals().pending_set(self.record);
        let blocked_pending = pending.intersect(blocked.signals());
        blocked_pending.bits()
    }

    fn kill(
        &mut self,
        pid: carrick_personality_linux::signal::SignalProcessSelector,
        request: carrick_personality_linux::signal::SignalRequest,
        info: carrick_personality_linux::signal::SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        let esrch = carrick_personality_linux::abi::signal::LINUX_ESRCH;
        let pid = pid.abi_number();
        let sig = request.number();
        let signal = request.signal();

        let graph = self.runtime.graph.lock();
        let caller_row = graph.owner.task(self.key).map_err(|_| esrch)?;
        let caller_pgid = caller_row.metadata().namespace_process_group;
        let caller_pid = caller_row.metadata().namespace_pid;

        let mut targets = alloc::vec::Vec::new();
        if pid > 0 {
            let target_pid = pid as u32;
            for (&_id, task) in graph.owner.tasks() {
                if task.metadata().namespace_pid == target_pid {
                    targets.push((
                        task.key(),
                        task.native().resources().signals().clone(),
                        task.parent(),
                    ));
                    break;
                }
            }
            if targets.is_empty() {
                if let Some(zombie) = graph
                    .owner
                    .zombies()
                    .values()
                    .find(|z| z.receipt.namespace_pid == target_pid)
                {
                    use carrick_personality_linux::signal::SignalTargetScope;
                    info.check_target(if zombie.receipt.key == self.key {
                        SignalTargetScope::CallingProcess
                    } else {
                        SignalTargetScope::OtherProcess
                    })?;
                    return Ok(());
                }
                return Err(esrch);
            }
        } else if pid == 0 {
            for (&_id, task) in graph.owner.tasks() {
                if task.metadata().namespace_process_group == caller_pgid {
                    targets.push((
                        task.key(),
                        task.native().resources().signals().clone(),
                        task.parent(),
                    ));
                }
            }
            if targets.is_empty() {
                return Err(esrch);
            }
        } else if pid == -1 {
            for (&_id, task) in graph.owner.tasks() {
                if task.metadata().namespace_pid != 1 && task.key() != self.key {
                    targets.push((
                        task.key(),
                        task.native().resources().signals().clone(),
                        task.parent(),
                    ));
                }
            }
            if targets.is_empty() {
                return Err(esrch);
            }
        } else {
            let target_pgid = pid.checked_abs().ok_or(esrch)? as u32;
            for (&_id, task) in graph.owner.tasks() {
                if task.metadata().namespace_process_group == target_pgid {
                    targets.push((
                        task.key(),
                        task.native().resources().signals().clone(),
                        task.parent(),
                    ));
                }
            }
            if targets.is_empty() {
                return Err(esrch);
            }
        }

        use carrick_personality_linux::signal::SignalTargetScope;
        for (key, _, _) in &targets {
            info.check_target(if *key == self.key {
                SignalTargetScope::CallingProcess
            } else {
                SignalTargetScope::OtherProcess
            })?;
        }
        if sig == 0 {
            return Ok(());
        }

        let Some(signal) = signal else {
            return Ok(());
        };
        let info = info.payload(signal).unwrap_or_else(|| {
            carrick_personality_linux::abi::signal::LinuxSiginfo::kill(
                sig,
                carrick_personality_linux::abi::signal::LINUX_SI_USER,
                caller_pid as i32,
                0,
            )
        });

        let mut wake_channels = Vec::new();
        let mut interrupts = Vec::new();
        for (target_key, target_signals, _) in targets {
            let before = interrupts.len();
            let _ = target_signals.enqueue(target_key, signal, Some(info));
            if let Ok(row) = graph.owner.task(target_key) {
                let resources = row.native().resources();
                let leader = resources.control.zone_record().unwrap_or(resources.record);
                let leader_mask = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                    carrick_signal_core::SignalSet::from_bits(resources.control.blocked().0),
                );
                if target_signals.has_deliverable(leader, leader_mask) {
                    interrupts.push(leader);
                }
                for index in 0..resources.page.entry_count() {
                    let Some((generation, state)) = resources.page.state(index) else {
                        continue;
                    };
                    if !matches!(
                        state,
                        carrick_el1_abi::EntryState::Born | carrick_el1_abi::EntryState::Published
                    ) {
                        continue;
                    }
                    let entry = EntryRef::new(index as u32, generation);
                    if let Some(address) = resources.page.control_address(entry)
                        && let Some(control) =
                            owned_control(resources.page, resources.control, address)
                        && let Some(record) = control.zone_record()
                        && record != leader
                    {
                        let mask = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                            carrick_signal_core::SignalSet::from_bits(control.blocked().0),
                        );
                        if target_signals.has_deliverable(record, mask) {
                            interrupts.push(record);
                        }
                    }
                }
            }
            if interrupts.len() != before
                && let Some(PendingContinuation::Ipc(pending)) = graph.pending.get(&target_key)
            {
                wake_channels.push(pending.channel.clone());
            }
            if let Some(channel) = graph
                .owner
                .task(target_key)
                .ok()
                .and_then(|t| t.native().resources().channel.clone())
            {
                wake_channels.push(channel);
            }
        }
        drop(graph);
        for record in interrupts {
            self.interrupt_signal_record(record);
        }
        for channel in wake_channels {
            self.publish_channel(&channel)
                .map_err(|error| carrick_syscall_abi::LinuxErrno::new(-error.errno() as i32))?;
        }
        Ok(())
    }

    fn tkill(
        &mut self,
        tid: carrick_personality_linux::signal::SignalThreadSelector,
        request: carrick_personality_linux::signal::SignalRequest,
        info: carrick_personality_linux::signal::SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        self.send_thread_signal(None, tid, request, info)
    }

    fn tgkill(
        &mut self,
        tgid: carrick_personality_linux::signal::SignalThreadSelector,
        tid: carrick_personality_linux::signal::SignalThreadSelector,
        request: carrick_personality_linux::signal::SignalRequest,
        info: carrick_personality_linux::signal::SignalInfo,
    ) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        let group = tgid.positive().ok_or(carrick_syscall_abi::LINUX_EINVAL)?;
        self.send_thread_signal(Some(group), tid, request, info)
    }

    fn rt_sigtimedwait(
        &mut self,
        set: carrick_signal_core::SignalSet,
        timeout_ns: Option<u64>,
        info: UserVa,
    ) -> Result<carrick_personality_linux::signal::SignalWaitOutcome, carrick_syscall_abi::LinuxErrno>
    {
        use carrick_personality_linux::signal::SignalWaitOutcome;
        use carrick_signal_core::policy::Signal;
        let set = set.without(Signal::KILL).without(Signal::STOP);
        let mut deadline = None;
        loop {
            let graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task(self.key)
                .map_err(|_| carrick_personality_linux::abi::signal::LINUX_ESRCH)?;
            let resources = row.native().resources();
            let signals = resources.signals();
            let channel = resources
                .channel
                .clone()
                .ok_or(carrick_personality_linux::abi::signal::LINUX_ESRCH)?;
            let generation = channel.generation.generation();
            if let Some((signal, payload)) = signals.take_timedwait(self.record, set) {
                return Ok(SignalWaitOutcome::Ready(signal, payload));
            }
            if timeout_ns == Some(0) {
                return Err(carrick_personality_linux::abi::signal::LINUX_EAGAIN);
            }
            let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(self.control.blocked().0),
            );
            if signals.has_deliverable(self.record, blocked) {
                return Err(carrick_personality_linux::abi::signal::LINUX_EINTR);
            }
            #[cfg(test)]
            if let Some(hook) = self.runtime.signal_check_hook.lock().take() {
                hook();
            }
            drop(graph);
            if deadline.is_none() {
                deadline = timeout_ns
                    .map(|nanos| self.service.signal_deadline(nanos))
                    .transpose()
                    .map_err(|error| carrick_syscall_abi::LinuxErrno::new(-error.errno() as i32))?;
            }
            if let Some(deadline) = deadline
                && self
                    .service
                    .signal_now()
                    .map_err(|error| carrick_syscall_abi::LinuxErrno::new(-error.errno() as i32))?
                    .raw()
                    >= deadline.0.raw()
            {
                return Err(carrick_personality_linux::abi::signal::LINUX_EAGAIN);
            }
            if self
                .park_signal_wait(
                    PendingSignalKind::Wait { set, info },
                    channel,
                    generation,
                    deadline,
                )
                .map_err(|error| carrick_syscall_abi::LinuxErrno::new(-error.errno() as i32))?
            {
                return Ok(SignalWaitOutcome::Pending);
            }
        }
    }
    fn rt_sigsuspend(
        &mut self,
        mask: carrick_signal_core::policy::SigBlockMask,
        original: carrick_signal_core::policy::SigBlockMask,
    ) -> Result<bool, carrick_syscall_abi::LinuxErrno> {
        if self
            .runtime
            .graph
            .lock()
            .suspend_masks
            .insert(self.record, original)
            .is_none()
        {
            NATIVE_SUSPEND_MASKS.fetch_add(1, Ordering::Release);
        }
        loop {
            let graph = self.runtime.graph.lock();
            let row = graph
                .owner
                .task(self.key)
                .map_err(|_| carrick_personality_linux::abi::signal::LINUX_ESRCH)?;
            let signals = row.native().resources().signals();
            let channel = row
                .native()
                .resources()
                .channel
                .clone()
                .ok_or(carrick_personality_linux::abi::signal::LINUX_ESRCH)?;
            let generation = channel.generation.generation();
            let available = signals.has_deliverable(self.record, mask);
            #[cfg(test)]
            if let Some(hook) = self.runtime.signal_check_hook.lock().take() {
                hook();
            }
            drop(graph);
            if available {
                return Ok(false);
            }
            match self.park_signal_wait(PendingSignalKind::Suspend, channel, generation, None) {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(error) => {
                    if self
                        .runtime
                        .graph
                        .lock()
                        .suspend_masks
                        .remove(&self.record)
                        .is_some()
                    {
                        NATIVE_SUSPEND_MASKS.fetch_sub(1, Ordering::Release);
                    }
                    return Err(carrick_syscall_abi::LinuxErrno::new(-error.errno() as i32));
                }
            }
        }
    }
    fn take_suspend_mask(&mut self) -> Option<carrick_signal_core::policy::SigBlockMask> {
        let old = self.runtime.graph.lock().suspend_masks.remove(&self.record);
        if old.is_some() {
            NATIVE_SUSPEND_MASKS.fetch_sub(1, Ordering::Release);
        }
        old.or_else(|| {
            self.control.take_forwarded_wait_mask().map(|saved| {
                carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                    carrick_signal_core::SignalSet::from_bits(saved.0),
                )
            })
        })
    }

    fn take_deliverable(
        &mut self,
        blocked: carrick_signal_core::policy::SigBlockMask,
    ) -> Option<(
        carrick_signal_core::policy::Signal,
        Option<carrick_personality_linux::abi::signal::LinuxSiginfo>,
        carrick_signal_core::policy::Action,
    )> {
        let graph = self.runtime.graph.lock();
        let row = graph.owner.task(self.key).ok()?;
        row.native()
            .resources()
            .signals()
            .take_deliverable(self.record, blocked)
    }
}

#[cfg(any(test, feature = "host-test"))]
pub mod host_test_support;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::drop_non_drop
)]
mod tests {
    #[test]
    fn native_signal_entry_keeps_absent_restart_context_off_stack() {
        type Entry = NativeProcessEntry<
            'static,
            'static,
            AddressContext<RootGpa>,
            ParkedContextWords,
            Physical<'static>,
        >;
        assert!(
            core::mem::size_of::<Entry>() <= core::mem::size_of::<ParkedContextWords>() + 384,
            "an absent interrupted wait must not duplicate a full native register/XSAVE context"
        );
    }

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

    use super::host_test_support::{Physical, words};
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa};
    use carrick_sched_core::ParkedContextWords;
    #[test]
    fn serial_host_empty_signal_checkpoint_takes_no_registry_or_graph_lock() {
        super::host_test_support::empty_signal_checkpoint_lock_witness();
    }
    #[test]
    fn compact_native_wait_bucket_uses_the_shared_hash_for_its_context_abi() {
        for (mm, address) in [(1, 0), (104, 0xffff_ffff_a800_0000), (u64::MAX, u64::MAX)] {
            assert_eq!(
                ZoneTables::<ParkedContextWords>::bucket_of_with_context(mm, address),
                ZoneTables::<carrick_sched_core::ThreadCtx>::bucket_of(mm, address)
            );
        }
    }
    #[test]
    fn process_clone_child_tid_lives_in_child_mm_and_clears_on_exit() {
        for child_copy_error in [
            None,
            Some(NativeProcessError::Fault),
            Some(NativeProcessError::Busy),
            Some(NativeProcessError::Stale),
        ] {
            let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
            // SAFETY: the aligned allocation owns the complete zero-valid compact zone.
            let zone = unsafe {
                let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
                assert!(!ptr.is_null());
                Box::from_raw(ptr)
            };
            let page = ThreadLifecyclePage::new();
            let control = ThreadControlSlot::new();
            let child_page = ThreadLifecyclePage::new();
            let child_controls = core::array::from_fn::<_, 9, _>(|_| ThreadControlSlot::new());
            let task = CurrentTask::new();
            task.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
            task.mm.key.store(1, Ordering::Release);
            task.mm.thread_generation.store(101, Ordering::Release);
            task.publish_visible_pid(41);
            task.publish_lifecycle(&page as *const _ as u64, &control as *const _ as u64);
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
                    lifecycle_page: &page as *const _ as u64,
                    control_slot: &control as *const _ as u64,
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
            let tid_va = UserVa::new(0x7000);
            let mut service = Physical {
                zone: &zone,
                page: &child_page,
                controls: &child_controls,
                copies: Vec::new(),
                tid_words: BTreeMap::from([((1, tid_va.raw()), 0xaaaa)]),
                tid_wakes: 0,
                tid_writes: Vec::new(),
                refuse_copy: false,
                child_copy_error,
                on_signal_clock: None,
            };
            let mut parent = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            let LifecycleOutcome::Returned { result, .. } = parent.fork(ProcessForkChildTid {
                address: tid_va,
                set: true,
                clear: true,
            }) else {
                panic!("clone process fork must return to parent");
            };
            assert_eq!(result.raw(), 42);
            let root_key = runtime.graph.lock().root_key;
            let child_key = runtime.namespace_child_key(root_key, 42).unwrap();
            let child = runtime.task_binding(child_key).unwrap();
            let child_mm = child.address.mm.raw().get();
            assert_ne!(child_mm, 1);
            assert_eq!(parent.service.tid_words[&(1, tid_va.raw())], 0xaaaa);
            assert_eq!(parent.service.tid_words[&(child_mm, tid_va.raw())], 0xaaaa);
            assert_eq!(child.words.syscall_return(), 0);
            let parent_record = zone
                .slot(slot)
                .current()
                .or_else(|| zone.slot(slot).host_record())
                .unwrap();
            drop(parent);
            zone.requeue_preempted(slot, parent_record);
            activate(&runtime, source, &task, child_key);
            let child_words = runtime.task_binding(child_key).unwrap().words;
            let mut child = runtime
                .enter(source, &task, child_words, &mut service)
                .unwrap();
            assert!(matches!(
                child.resume_checkpoint(),
                Ok(NativeResume::NoPending)
            ));
            assert_eq!(child.service.tid_words[&(1, tid_va.raw())], 0xaaaa);
            assert_eq!(
                child.service.tid_words[&(child_mm, tid_va.raw())],
                if child_copy_error.is_some() {
                    0xaaaa
                } else {
                    42
                }
            );
            assert_eq!(
                child.service.tid_writes.len(),
                usize::from(child_copy_error.is_none())
            );
            child.service.child_copy_error = None;
            assert_eq!(child.control.clear_child_tid(), tid_va.raw());
            // A waiter on the child's private futex must become runnable at exit.
            // Its key deliberately differs from the parent's identical VA.
            let waiter = zone
                .alloc_record(ThreadIdentity {
                    tid: 43,
                    serial: 103,
                    mm: child_mm,
                    file_table: 5,
                    generation: 12,
                    affinity: 1,
                    lifecycle_page: &child_page as *const _ as u64,
                    control_slot: &child_controls[1] as *const _ as u64,
                })
                .unwrap();
            let guard = zone.short_lock(
                ZoneTables::<ParkedContextWords>::bucket_of_with_context(child_mm, tid_va.raw()),
                &NativeBucketWait {
                    lifetime: core::marker::PhantomData,
                    probe: None,
                },
            );
            let sequence = zone.next_seq(waiter);
            zone.enqueue(
                &guard,
                waiter,
                sequence,
                child_mm,
                tid_va.raw(),
                u32::MAX,
                0,
            )
            .unwrap();
            zone.publish_park(waiter, sequence);
            drop(guard);
            assert!(matches!(
                zone.record(waiter).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));
            assert!(matches!(
                child.exit_group(0),
                LifecycleOutcome::Transferred { .. }
            ));
            assert_eq!(child.service.tid_words[&(child_mm, tid_va.raw())], 0);
            assert_eq!(
                child.service.tid_writes.last(),
                Some(&(child_mm, tid_va.raw(), 0))
            );
            assert_eq!(child.service.tid_words[&(1, tid_va.raw())], 0xaaaa);
            assert_eq!(child.service.tid_wakes, 1);
            assert!(matches!(
                zone.record(waiter).claim(),
                carrick_sched_core::Claim::Queued { .. }
            ));
        }
    }
    #[test]
    fn two_roots_in_one_carrier_have_independent_fork_and_wait_authority() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: the aligned allocation owns the complete zero-valid compact zone.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let registry = Box::leak(Box::new(NativeProcessRegistry::<
            AddressContext<RootGpa>,
            ParkedContextWords,
        >::new()));
        let pages = [ThreadLifecyclePage::new(), ThreadLifecyclePage::new()];
        let controls = [ThreadControlSlot::new(), ThreadControlSlot::new()];
        let child_pages = [ThreadLifecyclePage::new(), ThreadLifecyclePage::new()];
        let child_controls = [
            core::array::from_fn::<_, 9, _>(|_| ThreadControlSlot::new()),
            core::array::from_fn::<_, 9, _>(|_| ThreadControlSlot::new()),
        ];
        let tasks = [CurrentTask::new(), CurrentTask::new()];
        let mut runtimes = Vec::new();
        let mut addresses = Vec::new();
        for index in 0..2 {
            let tid = 41 + index as u64 * 10;
            let mm = 1 + index as u64 * 10;
            let root = 0x1000 + index as u64 * 0x2000;
            let slot = carrick_sched_core::SlotId::new(index as u8);
            let task = &tasks[index];
            task.set(
                carrick_el1_abi::El1TaskId::from_linux_tid(tid as i32),
                11 + index as u64,
                5,
            );
            task.mm.key.store(mm, Ordering::Release);
            task.mm
                .thread_generation
                .store(101 + index as u64, Ordering::Release);
            task.publish_visible_pid(tid as u32);
            task.publish_lifecycle(
                &pages[index] as *const _ as u64,
                &controls[index] as *const _ as u64,
            );
            let address = AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(root)).unwrap(),
                mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
                generation: ContextGeneration::new(NonZeroU64::MIN),
            };
            let space = zone.spaces.publish_closed(mm, root, 0).unwrap();
            zone.spaces.open(space);
            zone.drive(slot, 1);
            zone.publish_slot(slot, 1, Some(index as u32), 1);
            zone.enter_guest(slot);
            zone.install_space(slot, mm).unwrap();
            zone.current_or_new(
                slot,
                ThreadIdentity {
                    tid,
                    serial: 101 + index as u64,
                    mm,
                    file_table: 5,
                    generation: 11 + index as u64,
                    affinity: 1,
                    lifecycle_page: &pages[index] as *const _ as u64,
                    control_slot: &controls[index] as *const _ as u64,
                },
            )
            .unwrap();
            let source = BornInZoneSource { zone: &zone, slot };
            let runtime = Arc::new(
                NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                    source,
                    task,
                    &pages[index],
                    &controls[index],
                    address,
                    address,
                    words(address),
                )
                .unwrap(),
            );
            registry
                .register_root(runtime.clone(), source, task, address)
                .unwrap();
            runtimes.push(runtime);
            addresses.push(address);
        }
        // An ingress record authenticates the exact live native member, not
        // just a tid shared by two roots or a recycled record slot.
        let first_binding = crate::personality::common_entry::execution_binding(&tasks[0]);
        let first_record = registry
            .state
            .lock()
            .members
            .iter()
            .find(|(key, _)| key.task.id().raw() == 41)
            .unwrap()
            .1
            .record;
        let event = carrick_el1_abi::ExternalSignalRecord::new(
            carrick_core_abi::EntryEventIdentity::from_binding(first_binding),
            first_binding,
            first_record,
            carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::MIN),
            carrick_signal_core::policy::Signal::from_number(2).unwrap(),
            carrick_el1_abi::ExternalSignalSource::Terminal,
        );
        assert!(
            !registry.signal_checkpoint_needed(&zone, first_record),
            "empty native inbox skips the FP/SIMD save"
        );
        let owner = registry
            .for_external_event(&zone, event)
            .expect("live ingress owner");
        assert!(Arc::ptr_eq(&owner, &runtimes[0]));
        let stale = carrick_el1_abi::ExternalSignalRecord::new(
            event.identity(),
            ExecutionBinding {
                generation: carrick_core_abi::EntryGeneration::from_raw(
                    first_binding.generation.raw() + 1,
                ),
                ..first_binding
            },
            first_record,
            event.event_generation(),
            event.signal(),
            event.source(),
        );
        assert!(registry.for_external_event(&zone, stale).is_none());
        let recycled = carrick_el1_abi::ExternalSignalRecord::new(
            event.identity(),
            first_binding,
            RecordRef {
                incarnation: first_record.incarnation + 1,
                ..first_record
            },
            event.event_generation(),
            event.signal(),
            event.source(),
        );
        assert!(registry.for_external_event(&zone, recycled).is_none());
        let mut services = [
            Physical {
                zone: &zone,
                page: &child_pages[0],
                controls: &child_controls[0],
                copies: Vec::new(),
                tid_words: BTreeMap::new(),
                tid_wakes: 0,
                tid_writes: Vec::new(),
                refuse_copy: false,
                child_copy_error: None,
                on_signal_clock: None,
            },
            Physical {
                zone: &zone,
                page: &child_pages[1],
                controls: &child_controls[1],
                copies: Vec::new(),
                tid_words: BTreeMap::new(),
                tid_wakes: 0,
                tid_writes: Vec::new(),
                refuse_copy: false,
                child_copy_error: None,
                on_signal_clock: None,
            },
        ];
        assert!(
            registry
                .admit_external_event(
                    &zone,
                    event,
                    carrick_sched_core::SlotId::new(0),
                    &mut services[0],
                )
                .unwrap()
        );
        let signals = runtimes[0].current_signals(&tasks[0]).unwrap();
        assert!(signals.pending_set(first_record).contains(event.signal()));
        assert!(registry.signal_checkpoint_needed(&zone, first_record));
        let _ = signals.take_deliverable(
            first_record,
            carrick_signal_core::policy::SigBlockMask::NONE,
        );
        assert!(!registry.signal_checkpoint_needed(&zone, first_record));
        let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
        queue.admit(stale).unwrap();
        assert_eq!(
            registry
                .drain_external_ingress(
                    &zone,
                    &queue,
                    carrick_sched_core::SlotId::new(0),
                    &mut services[0],
                )
                .unwrap(),
            0
        );
        assert!(!signals.pending_set(first_record).contains(event.signal()));
        let queued = carrick_el1_abi::ExternalSignalRecord::new(
            event.identity(),
            event.binding(),
            event.record(),
            carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::new(2).unwrap()),
            event.signal(),
            event.source(),
        );
        queue.admit(queued).unwrap();
        assert_eq!(
            registry
                .drain_external_ingress(
                    &zone,
                    &queue,
                    carrick_sched_core::SlotId::new(0),
                    &mut services[0],
                )
                .unwrap(),
            1
        );
        assert!(signals.pending_set(first_record).contains(event.signal()));
        let _ = signals.take_deliverable(
            first_record,
            carrick_signal_core::policy::SigBlockMask::NONE,
        );
        // A queued process event may retain the pre-exec record while the
        // process task serial remains live. Admission must select that task
        // through the durable process key, not the obsolete record.
        let process_event = carrick_el1_abi::ExternalSignalRecord::new(
            event.identity(),
            event.binding(),
            RecordRef {
                incarnation: first_record.incarnation + 1,
                ..first_record
            },
            carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::new(3).unwrap()),
            event.signal(),
            event.source(),
        )
        .process_directed()
        .for_process(first_binding.task, first_binding.generation);
        assert!(registry.for_external_event(&zone, process_event).is_some());
        queue.admit(process_event).unwrap();
        assert_eq!(
            registry
                .drain_external_ingress(
                    &zone,
                    &queue,
                    carrick_sched_core::SlotId::new(0),
                    &mut services[0],
                )
                .unwrap(),
            1
        );
        assert!(signals.pending_set(first_record).contains(event.signal()));
        let _ = signals.take_deliverable(
            first_record,
            carrick_signal_core::policy::SigBlockMask::NONE,
        );
        let mut children = Vec::new();
        for index in 0..2 {
            let task = &tasks[index];
            let source = BornInZoneSource {
                zone: &zone,
                slot: carrick_sched_core::SlotId::new(index as u8),
            };
            let runtime = registry
                .for_entry(source, task, addresses[index])
                .expect("admitted root lookup succeeds");
            assert!(Arc::ptr_eq(&runtime, &runtimes[index]));
            let mut entry = runtime
                .enter_registered(
                    registry,
                    source,
                    task,
                    addresses[index],
                    words(addresses[index]),
                    &mut services[index],
                )
                .unwrap();
            let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
            else {
                panic!("fork return");
            };
            assert_eq!(result.raw(), 42 + index as i64 * 10);
            children.push(42 + index as u32 * 10);
        }
        for index in 0..2 {
            let task = &tasks[index];
            let source = BornInZoneSource {
                zone: &zone,
                slot: carrick_sched_core::SlotId::new(index as u8),
            };
            let runtime = registry.for_entry(source, task, addresses[index]).unwrap();
            let mut entry = runtime
                .enter_registered(
                    registry,
                    source,
                    task,
                    addresses[index],
                    words(addresses[index]),
                    &mut services[index],
                )
                .unwrap();
            let own_child = children[index];
            let foreign_child = children[1 - index];
            let LifecycleOutcome::Returned { result, .. } = entry.wait4(
                ProcessWaitPid::from_syscall_argument(foreign_child as u64),
                UserVa::new(0),
                LinuxWaitOptions::WNOHANG,
                UserVa::new(0),
            ) else {
                panic!("foreign wait return");
            };
            assert_eq!(result.raw(), NativeProcessError::NoChild.errno());
            let LifecycleOutcome::Returned { result, .. } = entry.wait4(
                ProcessWaitPid::from_syscall_argument(own_child as u64),
                UserVa::new(0),
                LinuxWaitOptions::WNOHANG,
                UserVa::new(0),
            ) else {
                panic!("own wait return");
            };
            assert_eq!(result.raw(), 0);
        }
        let foreign = CurrentTask::new();
        foreign.set(carrick_el1_abi::El1TaskId::from_linux_tid(99), 99, 5);
        foreign.mm.key.store(1, Ordering::Release);
        foreign.mm.thread_generation.store(101, Ordering::Release);
        assert!(matches!(
            registry.for_entry(
                BornInZoneSource {
                    zone: &zone,
                    slot: carrick_sched_core::SlotId::new(0)
                },
                &foreign,
                addresses[0]
            ),
            Err(NativeProcessError::Stale)
        ));
    }
    #[test]
    fn nonleader_thread_forks_through_its_authenticated_process_owner() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: the aligned allocation owns the complete zero-valid compact zone.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let registry = Box::leak(Box::new(NativeProcessRegistry::<
            AddressContext<RootGpa>,
            ParkedContextWords,
        >::new()));
        let page = ThreadLifecyclePage::new();
        let leader_control = ThreadControlSlot::new();
        let thread_control = ThreadControlSlot::new();
        let child_page = ThreadLifecyclePage::new();
        let child_controls = core::array::from_fn::<_, 9, _>(|_| ThreadControlSlot::new());
        let leader = CurrentTask::new();
        leader.set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
        leader.mm.key.store(1, Ordering::Release);
        leader.mm.thread_generation.store(101, Ordering::Release);
        leader.publish_visible_pid(41);
        leader.publish_lifecycle(&page as *const _ as u64, &leader_control as *const _ as u64);
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
                lifecycle_page: &page as *const _ as u64,
                control_slot: &leader_control as *const _ as u64,
            },
        )
        .unwrap();
        let source = BornInZoneSource { zone: &zone, slot };
        let thread = CurrentTask::new();
        let runtime = Arc::new(
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &leader,
                &page,
                &leader_control,
                address,
                address,
                words(address),
            )
            .unwrap(),
        );
        registry
            .register_root(runtime.clone(), source, &leader, address)
            .unwrap();

        let entry = page
            .stock(
                0,
                carrick_el1_abi::EntryIdentity {
                    tid: 43,
                    visible_tid: 43,
                    thread_serial: 103,
                    execution: carrick_core_abi::entry::EntryGeneration::from_raw(12),
                    uid_credit: 0,
                },
            )
            .unwrap();
        page.bind_control_address(entry, &thread_control as *const _ as u64)
            .unwrap();
        thread_control
            .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry)
            .unwrap();
        assert!(thread_control.publish_visible_tid(43));
        let claim = page.claim(entry).unwrap();
        page.record_born(
            claim,
            carrick_el1_abi::BornRecord {
                caller_task: 41,
                caller_serial: 101,
                clone_flags: 0x0001_0000,
                clear_child_tid: 0,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
        page.thread_born().unwrap();
        page.publish(entry).unwrap();
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 43,
                serial: 103,
                mm: 1,
                file_table: 5,
                generation: 13,
                affinity: 1,
                lifecycle_page: &page as *const _ as u64,
                control_slot: &thread_control as *const _ as u64,
            })
            .unwrap();
        thread_control.bind_zone_record(zone.record_ref(record));
        zone.requeue_preempted(slot, record);
        assert_eq!(zone.switch_in_full(slot).unwrap().record, record);
        thread.set(carrick_el1_abi::El1TaskId::from_linux_tid(43), 13, 5);
        thread.mm.key.store(1, Ordering::Release);
        thread.mm.thread_generation.store(103, Ordering::Release);
        thread.publish_visible_pid(41);
        thread.publish_lifecycle(&page as *const _ as u64, &thread_control as *const _ as u64);
        assert!(matches!(
            registry.for_entry(source, &thread, address),
            Err(NativeProcessError::Stale)
        ));
        assert!(matches!(
            registry.register_thread(source, &thread, address, &page, &leader_control),
            Err(NativeProcessError::Stale)
        ));
        registry
            .register_thread(source, &thread, address, &page, &thread_control)
            .unwrap();
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &child_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let mut process = runtime
            .enter_registered(
                registry,
                source,
                &thread,
                address,
                words(address),
                &mut service,
            )
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = process.fork(ProcessForkChildTid::NONE)
        else {
            panic!("thread fork return");
        };
        assert_eq!(result.raw(), 42);
        let leader_key = TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        assert!(runtime.namespace_child_key(leader_key, 42).is_some());
        let exit = process.exit_group(9);
        if let LifecycleOutcome::Returned { result, .. } = &exit {
            panic!("nonleader exit_group refused with {}", result.raw());
        }
        assert!(matches!(
            exit,
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
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
    fn signal_wait_owns_context_and_shared_deadline() {
        signal_wait_contract(false, false);
    }
    #[test]
    fn pending_default_stop_does_not_interrupt_sigtimedwait_or_sigsuspend() {
        signal_wait_contract(true, false);
    }
    #[test]
    fn pending_default_stop_does_not_interrupt_sigsuspend() {
        signal_wait_contract(true, true);
    }
    fn signal_wait_contract(default_stop: bool, suspend_only: bool) {
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        use carrick_personality_linux::signal::{ProcessSignals, SignalWaitOutcome};
        let set = carrick_signal_core::SignalSet::EMPTY
            .with(carrick_signal_core::policy::Signal::from_number(10).unwrap());
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let selector = carrick_personality_linux::signal::SignalThreadSelector::from_abi(41);
        assert_eq!(
            entry.tgkill(
                selector,
                selector,
                carrick_personality_linux::signal::SignalRequest::Probe,
                carrick_personality_linux::signal::SignalInfo::Generated(None)
            ),
            Ok(())
        );
        // kill(2): INT_MIN selects no representable process group.
        assert_eq!(
            entry.kill(
                carrick_personality_linux::signal::SignalProcessSelector::from_abi(
                    (i32::MIN) as u64
                ),
                carrick_personality_linux::signal::SignalRequest::from_abi(0).unwrap(),
                carrick_personality_linux::signal::SignalInfo::Generated(None)
            ),
            Err(carrick_syscall_abi::LinuxErrno::new(3))
        );
        assert_eq!(
            entry.kill(
                carrick_personality_linux::signal::SignalProcessSelector::from_abi((-1_i32) as u64),
                carrick_personality_linux::signal::SignalRequest::from_abi(0).unwrap(),
                carrick_personality_linux::signal::SignalInfo::Generated(None)
            ),
            Err(carrick_syscall_abi::LinuxErrno::new(3)),
            "kill(-1) excludes caller"
        );
        let ignored = carrick_signal_core::policy::Action {
            disposition: carrick_signal_core::policy::Disposition::Ignore,
            ..Default::default()
        };
        entry
            .rt_sigaction(
                carrick_signal_core::policy::Signal::from_number(10).unwrap(),
                Some(ignored),
            )
            .unwrap();
        let blocked = carrick_signal_core::policy::SigBlockMask::blocking_all_of(set);
        control.init_blocked(carrick_el1_abi::BlockedMask(set.bits()));
        entry
            .kill(
                carrick_personality_linux::signal::SignalProcessSelector::from_abi(41),
                carrick_personality_linux::signal::SignalRequest::from_abi(10).unwrap(),
                carrick_personality_linux::signal::SignalInfo::Generated(None),
            )
            .unwrap();
        assert_eq!(
            entry.rt_sigpending(blocked),
            set.bits(),
            "blocked ignored signal remains queued"
        );
        entry
            .rt_sigaction(
                carrick_signal_core::policy::Signal::from_number(10).unwrap(),
                Some(ignored),
            )
            .unwrap();
        assert_eq!(entry.rt_sigpending(blocked), 0);
        control.init_blocked(carrick_el1_abi::BlockedMask(0));
        if default_stop {
            entry
                .kill(
                    carrick_personality_linux::signal::SignalProcessSelector::from_abi(41),
                    carrick_personality_linux::signal::SignalRequest::Deliver(
                        carrick_signal_core::policy::Signal::STOP,
                    ),
                    carrick_personality_linux::signal::SignalInfo::Generated(None),
                )
                .unwrap();
        }
        if suspend_only {
            assert!(
                matches!(
                    entry.rt_sigsuspend(
                        carrick_signal_core::policy::SigBlockMask::NONE,
                        carrick_signal_core::policy::SigBlockMask::NONE,
                    ),
                    Ok(true)
                ),
                "default stop must park sigsuspend, not return EINTR"
            );
            assert!(entry.take_handoff_receipt().is_some());
            drop(entry);
            assert!(zone.slot(slot).current().is_none());
            return;
        }
        assert!(matches!(
            entry.rt_sigtimedwait(set, Some(1000), UserVa::new(0)),
            Ok(SignalWaitOutcome::Pending)
        ));
        assert!(entry.take_handoff_receipt().is_some());
        drop(entry);
        assert!(zone.slot(slot).current().is_none());
        let timer = zone.timer_owner(slot).unwrap();
        assert_eq!(zone.timer_deadline(slot), Some(2000));
        assert!(matches!(
            zone.live(timer.record).unwrap().claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        assert_eq!(zone.expire_timer(slot, 1999, (-11i64) as u64), Ok(false));
        assert_eq!(zone.expire_timer(slot, 2000, (-11i64) as u64), Ok(true));
        let selected = zone.switch_in_full(slot).unwrap();
        assert_eq!(zone.record_ref(selected.record), timer.record);
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        assert!(
            matches!(entry.resume_pending_wait(), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == -11)
        );
        assert!(
            !runtime
                .graph
                .lock()
                .signal_waits
                .contains_key(&entry.record)
        );
        assert!(zone.timer_owner(slot).is_none());
        if default_stop {
            assert!(
                matches!(
                    entry.rt_sigsuspend(
                        carrick_signal_core::policy::SigBlockMask::NONE,
                        carrick_signal_core::policy::SigBlockMask::NONE,
                    ),
                    Ok(true)
                ),
                "default stop must park sigsuspend, not return EINTR"
            );
            assert!(entry.take_handoff_receipt().is_some());
            drop(entry);
            assert!(zone.slot(slot).current().is_none());
            return;
        }
        drop(entry);

        // Inject precisely after the pending check and before park enrollment.
        // The wake must invalidate the pre-check generation, not be adopted as
        // the generation against which this new park is admitted.
        zone.counters.el1_timeouts.store(0, Ordering::Release);
        control.init_blocked(carrick_el1_abi::BlockedMask(set.bits()));
        let (signals, channel, key) = {
            let graph = runtime.graph.lock();
            let row = graph.owner.task(graph.root_key).unwrap();
            (
                row.native().resources().signals().clone(),
                row.native().resources().channel.clone().unwrap(),
                row.key(),
            )
        };
        let wake_channel = channel.clone();
        service.on_signal_clock = Some(Box::new(move || {
            signals
                .enqueue(
                    key,
                    carrick_signal_core::policy::Signal::from_number(
                        carrick_syscall_abi::LINUX_SIGUSR1,
                    )
                    .unwrap(),
                    None,
                )
                .unwrap();
            wake_channel.generation.publish().unwrap();
        }));
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let result = entry
            .resume_signal_wait(PendingSignalWait {
                kind: PendingSignalKind::Wait {
                    set,
                    info: UserVa::new(0),
                },
                channel,
                deadline: Some(carrick_guest_arch::Deadline(
                    carrick_guest_arch::CounterTick::new(2000),
                )),
            })
            .unwrap();
        assert!(
            matches!(result, LifecycleOutcome::Returned { result, .. } if result.raw() == 10),
            "a signal published after the queue check must prevent re-parking"
        );
        drop(entry);
        let (signals, channel, key) = {
            let graph = runtime.graph.lock();
            let row = graph.owner.task(graph.root_key).unwrap();
            (
                row.native().resources().signals().clone(),
                row.native().resources().channel.clone().unwrap(),
                row.key(),
            )
        };
        *runtime.signal_check_hook.lock() = Some(Box::new(move || {
            signals
                .enqueue(
                    key,
                    carrick_signal_core::policy::Signal::from_number(10).unwrap(),
                    None,
                )
                .unwrap();
            channel.generation.publish().unwrap();
        }));
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        assert!(
            matches!(entry.rt_sigtimedwait(set, Some(1000), UserVa::new(0)),
            Ok(SignalWaitOutcome::Ready(signal, _)) if signal.number() == 10),
            "publication after the initial pending check must not become the park generation"
        );
        drop(entry);
        let (signals, channel, key) = {
            let graph = runtime.graph.lock();
            let row = graph.owner.task(graph.root_key).unwrap();
            (
                row.native().resources().signals().clone(),
                row.native().resources().channel.clone().unwrap(),
                row.key(),
            )
        };
        let usr1 = carrick_signal_core::policy::Signal::from_number(10).unwrap();
        signals
            .install_action(
                key,
                usr1,
                carrick_signal_core::policy::Action {
                    disposition: carrick_signal_core::policy::Disposition::Handler(
                        carrick_signal_core::policy::HandlerAddress(0x4000),
                    ),
                    ..Default::default()
                },
            )
            .unwrap();
        *runtime.signal_check_hook.lock() = Some(Box::new(move || {
            signals.enqueue(key, usr1, None).unwrap();
            channel.generation.publish().unwrap();
        }));
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        assert_eq!(
            entry.rt_sigsuspend(
                carrick_signal_core::policy::SigBlockMask::NONE,
                carrick_signal_core::policy::SigBlockMask::NONE
            ),
            Ok(false),
            "suspend must also retry a publication after its initial pending check"
        );
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        assert!(zone.slot(slot).current().is_none());
        let home = zone.slot(slot).host_record().unwrap();
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        assert_eq!(page.thread_born(), Some(2));
        assert!(
            matches!(
                entry.exit_with_signal(15),
                Err(NativeProcessError::GroupExitCustody)
            ),
            "two-live-member signal termination must name its custody dependency"
        );
        assert_eq!(
            page.live(),
            2,
            "a refused group exit cannot retire shared memory"
        );
        page.release_live(1).unwrap();
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
    fn exit_failure_preserves_stale_cause() {
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        assert!(zone.slot(slot).current().is_none());
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        entry.set_calling_tid(9999);
        assert!(matches!(
            entry.exit_group(9),
            LifecycleOutcome::Transferred { .. }
        ));
        assert_eq!(
            entry.take_run_failure(),
            Some(carrick_core_abi::NativeRunFailureReason::NativeStale),
            "stale caller retains its true cause"
        );
    }
    // A fixture actor holds the enrollment bucket until main's committed
    // publisher reports contention. The completion flag releases it on the red
    // implementation's refusal, without sleeps or retrying the guest operation.
    fn release_bucket_when_publisher_waits<T>(
        guard: impl Send,
        waiting: &core::sync::atomic::AtomicBool,
        publish: impl FnOnce() -> T,
    ) -> T {
        let attempted = core::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let attempted = &attempted;
            let release = scope.spawn(move || {
                while !waiting.load(Ordering::Acquire) && !attempted.load(Ordering::Acquire) {
                    core::hint::spin_loop();
                }
                drop(guard);
            });
            struct Finished<'a>(&'a core::sync::atomic::AtomicBool);
            impl Drop for Finished<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let finished = Finished(attempted);
            let result = publish();
            drop(finished);
            release.join().unwrap();
            result
        })
    }
    #[test]
    fn exit_group_holds_terminal_custody_until_pre_live_claim_settles() {
        for (claim_live, wake_contention, resume_stale, signal_exit) in [
            (false, false, false, false),
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
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
                tid_words: BTreeMap::new(),
                tid_wakes: 0,
                tid_writes: Vec::new(),
                refuse_copy: false,
                child_copy_error: None,
                on_signal_clock: None,
            };
            assert!(zone.slot(slot).current().is_none());
            let home = zone.slot(slot).host_record().unwrap();
            let reached = std::sync::Barrier::new(2);
            let released = std::sync::Barrier::new(2);
            let probe = |attempt| {
                if attempt == LOCK_SPINS {
                    reached.wait();
                    released.wait();
                }
            };
            let mut entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            page.stock(
                0,
                EntryIdentity {
                    tid: 42,
                    visible_tid: 42,
                    thread_serial: 102,
                    execution: carrick_core_abi::entry::EntryGeneration::from_raw(12),
                    uid_credit: 0,
                },
            )
            .unwrap();
            let claim = page.claim_any().unwrap();
            if claim_live {
                assert_eq!(page.thread_born(), Some(2));
                entry.thread_spawned(41, 42, &mut || Ok(())).unwrap();
            }
            let expected_status = if signal_exit {
                LinuxWaitStatus::signaled(15, false)
            } else {
                LinuxWaitStatus::from_wait_encoding(9 << 8)
            };
            let outcome = if signal_exit {
                entry.exit_with_signal(15).unwrap()
            } else {
                entry.exit_group(9)
            };
            assert!(
                matches!(outcome, LifecycleOutcome::Transferred { .. }),
                "exit must suspend, never return guest EAGAIN"
            );
            assert_eq!(page.gate(), carrick_el1_abi::GateState::Closed);
            assert_eq!(page.live(), if claim_live { 1 } else { 0 });
            assert!(entry.take_run_failure().is_none());
            assert!(entry.take_root_exit().is_none());
            assert!(entry.take_handoff_receipt().is_some());
            assert_eq!(
                zone.record(home).resume_disposition(),
                carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(
                    if signal_exit {
                        OwnerEntry::Exception
                    } else {
                        OwnerEntry::Syscall
                    }
                )
            );
            assert_eq!(zone.slot(slot).queued(), 0);
            assert_eq!(
                entry.thread_spawned(41, 42, &mut || panic!("terminal close admitted Born")),
                Err(-11)
            );
            page.unclaim(claim).unwrap();
            let channel = runtime
                .graph
                .lock()
                .pending_exit
                .get(&entry.key)
                .unwrap()
                .channel
                .clone();
            assert_eq!(channel.generation.generation().raw(), 0);
            if claim_live {
                let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
                    carrick_core_abi::ExecutionBinding {
                        task: carrick_core_abi::entry::EntryTaskKey::from_raw(41),
                        generation: carrick_core_abi::entry::EntryGeneration::from_raw(11),
                        mm: carrick_core_abi::entry::EntryMmKey::from_raw(1),
                        thread_generation: carrick_core_abi::entry::EntryThreadGeneration::from_raw(
                            102,
                        ),
                    },
                    None,
                    carrick_sched_core::process::TerminationStatus::exited(0),
                )
                .unwrap();
                let (_terminal, membership) = carrick_core::terminal::TerminalCustody::<
                    carrick_core::terminal::Thread,
                    carrick_core::terminal::Live,
                >::admitted(identity)
                .begin()
                .reserve_nonfinal(&*page)
                .unwrap_or_else(|_| panic!("last sibling must retire during close"));
                membership.publish();
                entry.retire_thread_identity(42);
                entry.lifecycle_admission_settled().unwrap();
                assert_eq!(channel.generation.generation().raw(), 1);
                assert_eq!(entry.take_run_failure(), None);
            }
            // Claim owners deliver their settlement only after rollback is complete.
            // Direct hook invocation models that production lifecycle notification.
            if wake_contention {
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
                std::thread::scope(|scope| {
                    scope.spawn(|| {
                        let guard = guard;
                        reached.wait();
                        drop(guard);
                        released.wait();
                    });
                    entry.publication_wait_probe = Some(&probe);
                    entry.lifecycle_admission_settled().unwrap();
                    entry.publication_wait_probe = None;
                });
                assert_eq!(entry.take_run_failure(), None);
            }
            entry.lifecycle_admission_settled().unwrap();
            assert_eq!(zone.slot(slot).queued(), 1);
            let published = channel.generation.generation();
            entry.lifecycle_admission_settled().unwrap();
            assert_eq!(
                channel.generation.generation(),
                published,
                "wake custody has one publisher"
            );
            assert_eq!(published.raw(), 1, "terminal readiness publishes one wake");
            assert_eq!(zone.slot(slot).queued(), 1);
            assert!(matches!(
                page.claim_any(),
                Err(carrick_el1_abi::TransitionError::GateClosed(_))
            ));
            assert!(
                matches!(entry.fork(ProcessForkChildTid::NONE), LifecycleOutcome::Returned { result, .. } if result.raw() == -11)
            );
            drop(entry);
            let selected = zone.switch_in_full(slot).unwrap();
            assert_eq!(selected.record, home);
            let mut entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            if resume_stale {
                entry.set_calling_tid(9999);
            }
            assert!(matches!(
                entry.resume_pending_lifecycle(),
                Some(LifecycleOutcome::Transferred { .. })
            ));
            if resume_stale {
                assert_eq!(
                    entry.take_run_failure(),
                    Some(carrick_core_abi::NativeRunFailureReason::NativeStale)
                );
                assert!(entry.take_root_exit().is_none());
                assert_eq!(page.live(), 0);
                continue;
            }
            assert_eq!(entry.take_root_exit(), Some(expected_status));
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
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
                execution: carrick_core_abi::entry::EntryGeneration::from_raw(12),
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
        // Closing retains the admitted Born member and parks the leader until
        // cancellation returns its exact retirement receipt.
        assert_eq!(zone.slot(slot).queued(), 0);
        assert!(matches!(
            entry.exit_owned(9),
            Ok(LifecycleOutcome::Transferred { .. })
        ));
        assert_eq!(entry.take_run_failure(), None);
        assert!(entry.take_handoff_receipt().is_some());
        assert!(entry.take_root_exit().is_none());
        assert!(entry.has_thread(42));
        assert_eq!(page.live(), 1);
        assert_eq!(zone.record(child).claim(), carrick_sched_core::Claim::Free);
        assert!(runtime.graph.lock().owner.task(entry.key).is_ok());
        assert_eq!(zone.record_ref(child), child_ref);
        assert_eq!(zone.record(child).identity().tid, 42);
        assert_eq!(page.state(0).unwrap().1, carrick_el1_abi::EntryState::Born);
    }
    #[test]
    fn actual_compact_root_forks_a_shared_owner_child_with_distinct_visible_identity() {
        compact_root_fork_wait_contract(false, false, false, false, None);
    }
    #[test]
    fn caught_signal_interrupts_an_already_parked_owned_child_wait() {
        compact_root_fork_wait_contract(true, false, false, false, None);
    }
    #[test]
    fn reapable_child_wins_over_its_caught_sigchld() {
        compact_root_fork_wait_contract(false, true, false, false, None);
    }
    #[test]
    fn pending_default_stop_does_not_interrupt_wait4() {
        compact_root_fork_wait_contract(false, false, true, false, None);
    }
    #[test]
    fn child_signal_exit_preserves_status_across_birth_claim_settlement() {
        compact_root_fork_wait_contract(false, true, false, true, None);
    }
    #[test]
    fn child_exit_retains_wake_custody_across_parent_bucket_contention() {
        compact_root_fork_wait_contract(
            false,
            true,
            false,
            false,
            Some(LinuxWaitStatus::exited(7)),
        );
    }
    #[test]
    fn child_signal_exit_retains_wake_custody_across_parent_bucket_contention() {
        compact_root_fork_wait_contract(
            false,
            true,
            false,
            false,
            Some(LinuxWaitStatus::signaled(15, false)),
        );
    }
    fn compact_root_fork_wait_contract(
        interrupt_wait: bool,
        catch_child_exit: bool,
        default_stop: bool,
        signal_exit_continuation: bool,
        exit_wake_contended: Option<LinuxWaitStatus>,
    ) {
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let parent = TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let child;
        {
            let mut entry = runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap();
            if interrupt_wait || catch_child_exit {
                use carrick_personality_linux::signal::ProcessSignals;
                use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
                entry
                    .rt_sigaction(
                        Signal::from_number(if catch_child_exit { 17 } else { 10 }).unwrap(),
                        Some(Action {
                            disposition: Disposition::Handler(HandlerAddress(0x4000)),
                            ..Action::default()
                        }),
                    )
                    .unwrap();
            }
            let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
            else {
                panic!("fork return")
            };
            assert_eq!(result.raw(), 42);
            let parent = TaskKey {
                id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
                serial: TaskSerial::from_raw_u64(11).unwrap(),
            };
            child = runtime.namespace_child_key(parent, 42).unwrap();
            assert_ne!(child, parent);
            assert_eq!(
                runtime.graph.lock().owner.task(child).unwrap().parent(),
                Some(parent)
            );
            if default_stop {
                use carrick_personality_linux::signal::ProcessSignals;
                entry
                    .kill(
                        carrick_personality_linux::signal::SignalProcessSelector::from_abi(41),
                        carrick_personality_linux::signal::SignalRequest::Deliver(
                            carrick_signal_core::policy::Signal::STOP,
                        ),
                        carrick_personality_linux::signal::SignalInfo::Generated(None),
                    )
                    .unwrap();
            }
            let waiting = core::sync::atomic::AtomicBool::new(false);
            let probe = |attempt| {
                if attempt == LOCK_SPINS {
                    waiting.store(true, Ordering::Release);
                }
            };
            let guards = default_stop.then(|| {
                (0..carrick_sched_core::ZONE_BUCKETS)
                    .map(|bucket| zone.lock(bucket, &BoundedSpin(0)).unwrap())
                    .collect::<Vec<_>>()
            });
            entry.publication_wait_probe = Some(&probe);
            let outcome = release_bucket_when_publisher_waits(guards, &waiting, || {
                entry.wait4(
                    ProcessWaitPid::from_syscall_argument(u64::MAX),
                    UserVa::new(0x8000),
                    LinuxWaitOptions::empty(),
                    UserVa::new(0),
                )
            });
            entry.publication_wait_probe = None;
            if default_stop {
                assert!(
                    waiting.load(Ordering::Acquire),
                    "wait4 must reach the held bucket"
                );
            }
            if let LifecycleOutcome::Returned { result, .. } = outcome {
                panic!("wait4 contention returned {}", result.raw());
            }
            assert!(
                matches!(
                    outcome,
                    LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        ..
                    }
                ),
                "wait4 contention must not return errno"
            );
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
        assert_ne!(
            child_identity.file_table, 5,
            "plain fork owns its descriptor table"
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
            let waiting = core::sync::atomic::AtomicBool::new(false);
            let probe = |attempt| {
                if attempt == LOCK_SPINS {
                    waiting.store(true, Ordering::Release);
                }
            };
            let mut child_entry = runtime
                .enter(source, &task, child_words, &mut service)
                .unwrap();
            use carrick_personality_linux::signal::{ProcessSignals, SignalInfo};
            let forged = carrick_syscall_abi::LinuxSiginfo::kill(
                10,
                carrick_syscall_abi::LINUX_SI_USER,
                42,
                0,
            );
            assert_eq!(
                child_entry.kill(
                    carrick_personality_linux::signal::SignalProcessSelector::from_abi(41),
                    carrick_personality_linux::signal::SignalRequest::from_abi(0).unwrap(),
                    SignalInfo::Queued(forged)
                ),
                Err(carrick_syscall_abi::LinuxErrno::new(1))
            );
            let queued = carrick_syscall_abi::LinuxSiginfo::kill(
                10,
                carrick_syscall_abi::LINUX_SI_QUEUE,
                42,
                0,
            );
            assert_eq!(
                child_entry.kill(
                    carrick_personality_linux::signal::SignalProcessSelector::from_abi(41),
                    carrick_personality_linux::signal::SignalRequest::from_abi(0).unwrap(),
                    SignalInfo::Queued(queued)
                ),
                Ok(())
            );
            assert_eq!(
                child_entry.kill(
                    carrick_personality_linux::signal::SignalProcessSelector::from_abi(42),
                    carrick_personality_linux::signal::SignalRequest::from_abi(0).unwrap(),
                    SignalInfo::Queued(forged)
                ),
                Ok(())
            );
            let selector = carrick_personality_linux::signal::SignalThreadSelector::from_abi(41);
            let forged_thread = carrick_syscall_abi::LinuxSiginfo::kill(
                10,
                carrick_syscall_abi::LINUX_SI_TKILL,
                42,
                0,
            );
            assert_eq!(
                child_entry.tgkill(
                    selector,
                    selector,
                    carrick_personality_linux::signal::SignalRequest::Probe,
                    SignalInfo::Queued(forged_thread)
                ),
                Err(carrick_syscall_abi::LinuxErrno::new(1))
            );
            if interrupt_wait {
                use carrick_personality_linux::signal::{SignalProcessSelector, SignalRequest};
                child_entry
                    .kill(
                        SignalProcessSelector::from_abi(41),
                        SignalRequest::from_abi(10).unwrap(),
                        SignalInfo::Generated(None),
                    )
                    .unwrap();
                assert!(matches!(
                    child_entry.rt_sigsuspend(
                        carrick_signal_core::policy::SigBlockMask::NONE,
                        carrick_signal_core::policy::SigBlockMask::NONE
                    ),
                    Ok(true)
                ));
                assert!(child_entry.take_handoff_receipt().is_some());
                drop(child_entry);
                activate(&runtime, source, &task, parent);
                let mut parent_entry = runtime
                    .enter(source, &task, words(address), &mut service)
                    .unwrap();
                let Some(LifecycleOutcome::Returned { result, .. }) =
                    parent_entry.resume_pending_wait()
                else {
                    panic!("caught signal must resume the parked child wait");
                };
                assert_eq!(
                    result.raw(),
                    carrick_syscall_abi::LINUX_EINTR.guest_retval()
                );
                assert_eq!(
                    parent_entry.take_interrupted_child_wait(),
                    Some(words(address))
                );
                assert!(
                    runtime.namespace_child_key(parent, 42).is_some(),
                    "interruption cannot reap the live child"
                );
                return;
            }
            let parent_bucket = exit_wake_contended.map(|_| {
                (0..carrick_sched_core::ZONE_BUCKETS)
                    .map(|bucket| zone.lock(bucket, &BoundedSpin(0)).unwrap())
                    .collect::<Vec<_>>()
            });
            if signal_exit_continuation {
                child_page
                    .stock(
                        1,
                        EntryIdentity {
                            tid: 43,
                            visible_tid: 43,
                            thread_serial: 103,
                            execution: carrick_core_abi::entry::EntryGeneration::from_raw(12),
                            uid_credit: 0,
                        },
                    )
                    .unwrap();
                let claim = child_page.claim_any().unwrap();
                assert!(matches!(
                    child_entry.exit_with_signal(15).unwrap(),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(child_entry.take_handoff_receipt().is_some());
                assert!(child_entry.take_root_exit().is_none());
                assert_eq!(child_page.live(), 0);
                child_page.unclaim(claim).unwrap();
                child_entry.lifecycle_admission_settled().unwrap();
                drop(child_entry);
                activate(&runtime, source, &task, child);
                let mut resumed = runtime
                    .enter(source, &task, child_words, &mut service)
                    .unwrap();
                assert!(matches!(
                    resumed.resume_pending_lifecycle(),
                    Some(LifecycleOutcome::Transferred { .. })
                ));
                assert!(resumed.take_root_exit().is_none());
                assert!(resumed.take_handoff_receipt().is_some());
            } else {
                let outcome = if let Some(parent_bucket) = parent_bucket {
                    let status = exit_wake_contended.unwrap();
                    child_entry.publication_wait_probe = Some(&probe);
                    let result =
                        release_bucket_when_publisher_waits(parent_bucket, &waiting, || {
                            if let Some(signal) = status.term_signal() {
                                child_entry.exit_with_signal(signal)
                            } else {
                                Ok(child_entry.exit_group(7))
                            }
                        });
                    child_entry.publication_wait_probe = None;
                    assert!(
                        waiting.load(Ordering::Acquire),
                        "exit must reach a held bucket"
                    );
                    result.unwrap()
                } else {
                    child_entry.exit_group(7)
                };
                assert!(matches!(
                    outcome,
                    LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        ..
                    }
                ));
                assert_eq!(
                    child_entry.take_run_failure(),
                    None,
                    "normal parent enrollment contention must retain exit wake custody"
                );
                assert!(child_entry.take_handoff_receipt().is_some());
            }
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
            use carrick_personality_linux::signal::ProcessSignals;
            if signal_exit_continuation || exit_wake_contended.is_some() {
                let (signal, info, _) = parent_entry
                    .take_deliverable(carrick_signal_core::policy::SigBlockMask::NONE)
                    .expect("child termination must notify its parent");
                assert_eq!(signal.number(), 17);
                let info = info.unwrap();
                let code = info.si_code;
                let signaled = signal_exit_continuation
                    || exit_wake_contended.is_some_and(|status| status.term_signal().is_some());
                assert_eq!(
                    code,
                    if signaled {
                        carrick_syscall_abi::LINUX_CLD_KILLED
                    } else {
                        carrick_syscall_abi::LINUX_CLD_EXITED
                    }
                );
                assert_eq!(info.si_addr as u32, 42);
                assert_eq!(
                    i32::from_le_bytes(info._pad[..4].try_into().unwrap()),
                    if signaled { 15 } else { 7 }
                );
            }
            assert_eq!(
                parent_entry.kill(
                    carrick_personality_linux::signal::SignalProcessSelector::from_abi(42),
                    carrick_personality_linux::signal::SignalRequest::from_abi(15).unwrap(),
                    carrick_personality_linux::signal::SignalInfo::Generated(None)
                ),
                Ok(()),
                "zombie target exists"
            );
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
        if signal_exit_continuation || exit_wake_contended.is_some() {
            let copied = parent_entry.service.copies.last().unwrap();
            assert_eq!(
                *copied,
                exit_wake_contended.unwrap_or(LinuxWaitStatus::signaled(15, false))
            );
        }
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
    fn delayed_child_exit_notifies_adopter_when_selected_parent_exits_on_peer() {
        reparented_exit_notification_contract(true, true);
    }
    #[test]
    fn delayed_child_exit_uses_adopter_interest_when_old_parent_ignored_default() {
        reparented_exit_notification_contract(false, true);
    }
    #[test]
    fn delayed_child_exit_does_not_inherit_departed_parents_signal_interest() {
        reparented_exit_notification_contract(true, false);
    }
    fn reparented_exit_notification_contract(parent_caught: bool, adopter_caught: bool) {
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
                affinity: 3, // fixture owns both CPU slots before either fork
                lifecycle_page: &*page as *const _ as u64,
                control_slot: &*control as *const _ as u64,
            },
        )
        .unwrap();
        let source = BornInZoneSource { zone: &zone, slot };
        assert_eq!(page.thread_born(), Some(2)); // retained legacy bootstrap census
        page.release_live(1).unwrap(); // fixture settles its bootstrap census
        let grandchild_page = Box::new(ThreadLifecyclePage::new());
        let grandchild_controls = core::array::from_fn::<_, 9, _>(|_| ThreadControlSlot::new());
        let peer_task = CurrentTask::new();
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        use carrick_personality_linux::signal::ProcessSignals;
        use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
        let root = runtime.graph.lock().root_key;
        let root_signals = runtime
            .graph
            .lock()
            .owner
            .task(root)
            .unwrap()
            .native()
            .resources()
            .signals
            .clone();
        let root_channel = runtime
            .graph
            .lock()
            .owner
            .task(root)
            .unwrap()
            .native()
            .resources()
            .channel
            .clone()
            .unwrap();
        let mut root_entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        root_entry
            .rt_sigaction(
                Signal::CHLD,
                Some(Action {
                    disposition: Disposition::Handler(HandlerAddress(0x4000)),
                    ..Action::default()
                }),
            )
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = root_entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("parent fork")
        };
        let parent = runtime
            .namespace_child_key(root, result.raw() as u32)
            .unwrap();
        if !adopter_caught {
            root_entry
                .rt_sigaction(Signal::CHLD, Some(Action::default()))
                .unwrap();
        }
        assert!(matches!(
            root_entry.wait4(
                ProcessWaitPid::from_syscall_argument(u64::MAX),
                UserVa::new(0x8000),
                LinuxWaitOptions::empty(),
                UserVa::new(0)
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        drop(root_entry);
        activate(&runtime, source, &task, parent);
        let parent_address = runtime
            .graph
            .lock()
            .owner
            .task(parent)
            .unwrap()
            .native()
            .resources()
            .address;
        let parent_signals = runtime
            .graph
            .lock()
            .owner
            .task(parent)
            .unwrap()
            .native()
            .resources()
            .signals
            .clone();
        let parent_channel = runtime
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
        // The grandchild owns a distinct lifecycle page and runs on CPU 1.
        let mut parent_service = Physical {
            zone: &zone,
            page: &grandchild_page,
            controls: &grandchild_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let mut parent_entry = runtime
            .enter(source, &task, words(parent_address), &mut parent_service)
            .unwrap();
        if !parent_caught {
            parent_entry
                .rt_sigaction(Signal::CHLD, Some(Action::default()))
                .unwrap();
        }
        let LifecycleOutcome::Returned { result, .. } =
            parent_entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("child fork")
        };
        let child = runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap();
        drop(parent_entry);
        let child_record = runtime
            .graph
            .lock()
            .owner
            .task(child)
            .unwrap()
            .native()
            .resources()
            .record;
        let child_address = runtime
            .graph
            .lock()
            .owner
            .task(child)
            .unwrap()
            .native()
            .resources()
            .address;
        let peer_slot = carrick_sched_core::SlotId::new(1);
        zone.drive(peer_slot, 1);
        zone.publish_slot(peer_slot, 1, Some(1), 1);
        zone.enter_guest(peer_slot);
        assert_eq!(
            zone.claim_for_host(child_record, None, Handback::Resumed, &BoundedSpin(0)),
            carrick_sched_core::HostClaim::Claimed
        );
        assert!(zone.requeue_on(peer_slot, child_record.id));
        let peer_source = BornInZoneSource {
            zone: &zone,
            slot: peer_slot,
        };
        activate(&runtime, peer_source, &peer_task, child);
        let before = root_channel.generation.generation();
        let parent_before = parent_channel.generation.generation();
        let probe_calls = core::sync::atomic::AtomicU32::new(0);
        let probe = || {
            assert_eq!(probe_calls.fetch_add(1, Ordering::AcqRel), 0);
            assert_eq!(
                runtime
                    .graph
                    .lock()
                    .owner
                    .zombies()
                    .get(&child.id)
                    .unwrap()
                    .receipt
                    .parent,
                Some(parent)
            );
            std::thread::scope(|scope| {
                let (done, completed) = std::sync::mpsc::channel();
                scope.spawn(move || {
                    if completed
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .is_err()
                    {
                        // A scope panic still joins a wedged peer. Terminate the
                        // test process so a lock-order regression cannot hang CI.
                        std::process::abort();
                    }
                });
                let peer = scope.spawn(|| {
                    let mut service = Physical {
                        zone: &zone,
                        page: &grandchild_page,
                        controls: &grandchild_controls,
                        copies: Vec::new(),
                        tid_words: BTreeMap::new(),
                        tid_wakes: 0,
                        tid_writes: Vec::new(),
                        refuse_copy: false,
                        child_copy_error: None,
                        on_signal_clock: None,
                    };
                    let mut entry = runtime
                        .enter(source, &task, words(parent_address), &mut service)
                        .unwrap();
                    assert!(matches!(
                        entry.exit_group(9),
                        LifecycleOutcome::Transferred { .. }
                    ));
                    assert_eq!(entry.take_run_failure(), None, "peer parent exit");
                });
                let result = peer.join();
                done.send(()).unwrap();
                result.unwrap();
            });
            if adopter_caught {
                let (_, info) = root_signals
                    .take_timedwait(
                        child_record,
                        carrick_signal_core::SignalSet::EMPTY.with(Signal::CHLD),
                    )
                    .unwrap();
                let info = info.unwrap();
                assert_eq!(info.si_addr as u32, parent.id.raw() as u32);
            } else {
                assert_eq!(root_signals.pending_count(), 0);
            }
            let graph = runtime.graph.lock();
            assert!(
                graph.owner.task(parent).is_err(),
                "exact parent generation retired"
            );
            assert_eq!(
                graph.owner.zombies().get(&child.id).unwrap().receipt.parent,
                Some(root)
            );
        };
        let mut child_service = Physical {
            zone: &zone,
            page: &grandchild_page,
            controls: &grandchild_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let mut entry = runtime
            .enter(
                peer_source,
                &peer_task,
                words(child_address),
                &mut child_service,
            )
            .unwrap();
        entry.exit_notification_probe = Some(&probe);
        assert!(matches!(
            entry.exit_group(7),
            LifecycleOutcome::Transferred { .. }
        ));
        assert_eq!(
            entry.take_run_failure(),
            None,
            "reparented child exit must not fail the carrier"
        );
        assert!(entry.take_handoff_receipt().is_some());
        drop(entry);
        assert_eq!(
            probe_calls.load(Ordering::Acquire),
            1,
            "one final publication, no retry"
        );
        assert_eq!(
            parent_signals.pending_count(),
            0,
            "no delivery to departed parent"
        );
        assert_eq!(
            parent_channel.generation.generation(),
            parent_before,
            "no stale channel publication"
        );
        // Parent and child each publish once to the adopter. Standard SIGCHLD
        // coalesces; consume the parent's signal inside the probe to inspect C.
        assert_eq!(root_channel.generation.generation().raw(), before.raw() + 2);
        assert_eq!(
            zone.counters.el1_wakes.load(Ordering::Acquire),
            1,
            "one enrolled root waiter"
        );
        if adopter_caught {
            let (_, info) = root_signals
                .take_timedwait(
                    child_record,
                    carrick_signal_core::SignalSet::EMPTY.with(Signal::CHLD),
                )
                .unwrap();
            let info = info.unwrap();
            assert_eq!(info.si_addr as u32, child.id.raw() as u32);
            let code = info.si_code;
            assert_eq!(code, carrick_syscall_abi::LINUX_CLD_EXITED);
            assert_eq!(i32::from_le_bytes(info._pad[0..4].try_into().unwrap()), 7);
        } else {
            assert_eq!(
                root_signals.pending_count(),
                0,
                "current adopter policy suppresses SIGCHLD"
            );
        }
        activate(&runtime, source, &task, root);
        let mut root_entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let Some(LifecycleOutcome::Returned { result, .. }) = root_entry.resume_pending_wait()
        else {
            panic!("root wait resumes")
        };
        assert_eq!(result.raw(), parent.id.raw() as i64);
        let LifecycleOutcome::Returned { result, .. } = root_entry.wait4(
            ProcessWaitPid::from_syscall_argument(child.id.raw() as u64),
            UserVa::new(0x8000),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        ) else {
            panic!("adopter reaps child")
        };
        assert_eq!(result.raw(), child.id.raw() as i64);
        drop(root_entry);
        assert_eq!(
            service.copies,
            [LinuxWaitStatus::exited(9), LinuxWaitStatus::exited(7)]
        );
    }
    #[test]
    fn child_exit_group_waits_for_parent_bucket_and_delivers_status() {
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let parent = TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("fork")
        };
        let child_pid = result.raw();
        let child = runtime
            .namespace_child_key(parent, child_pid as u32)
            .unwrap();
        assert!(matches!(
            entry.wait4(
                ProcessWaitPid::from_syscall_argument(child_pid as u64),
                UserVa::new(0x8000),
                LinuxWaitOptions::empty(),
                UserVa::new(0)
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_handoff_receipt().is_some());
        drop(entry);
        let channel = runtime
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
        let before = channel.generation.generation();
        activate(&runtime, source, &task, child);
        let child_address = runtime
            .graph
            .lock()
            .owner
            .task(child)
            .unwrap()
            .native()
            .resources()
            .address;
        let guard = zone
            .lock(
                ZoneTables::<ParkedContextWords>::bucket_of_with_context(
                    channel.mm,
                    WaitChannel::address(&channel),
                ),
                &BoundedSpin(LOCK_SPINS),
            )
            .unwrap();
        let reached = std::sync::Barrier::new(2);
        let released = std::sync::Barrier::new(2);
        let probe = |attempt| {
            if attempt == LOCK_SPINS {
                reached.wait();
                released.wait();
            }
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let guard = guard;
                reached.wait();
                assert_eq!(channel.generation.generation(), before);
                drop(guard);
                released.wait();
            });
            let mut entry = runtime
                .enter(source, &task, words(child_address), &mut service)
                .unwrap();
            entry.publication_wait_probe = Some(&probe);
            assert!(matches!(
                entry.exit_group(19),
                LifecycleOutcome::Transferred { .. }
            ));
            assert_eq!(
                entry.take_run_failure(),
                None,
                "bucket contention cannot terminate the run"
            );
            assert!(entry.take_handoff_receipt().is_some());
        });
        assert_eq!(channel.generation.generation().raw(), before.raw() + 1);
        assert_eq!(child_page.live(), 0);
        activate(&runtime, source, &task, parent);
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        let Some(LifecycleOutcome::Returned { result, .. }) = entry.resume_pending_wait() else {
            panic!("parent resume")
        };
        assert_eq!(result.raw(), child_pid);
        assert_eq!(
            service.copies.last(),
            Some(&LinuxWaitStatus::from_wait_encoding(19 << 8))
        );
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
            let descendant_pages = [ThreadLifecyclePage::new(), ThreadLifecyclePage::new()];
            let descendant_controls: [[ThreadControlSlot; 9]; 2] =
                core::array::from_fn(|_| core::array::from_fn(|_| ThreadControlSlot::new()));
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
                tid_words: BTreeMap::new(),
                tid_wakes: 0,
                tid_writes: Vec::new(),
                refuse_copy: false,
                child_copy_error: None,
                on_signal_clock: None,
            };
            let parent = TaskKey {
                id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
                serial: TaskSerial::from_raw_u64(11).unwrap(),
            };
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
                let LifecycleOutcome::Returned { result, .. } =
                    entry.fork(ProcessForkChildTid::NONE)
                else {
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
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
        let child_pid = entry
            .fork_owned(ProcessForkChildTid::NONE)
            .expect("fork from thread 42 succeeds");
        drop(entry);

        let graph = runtime.graph.lock();
        let child_task = graph
            .owner
            .namespace_key(graph.root_key, child_pid)
            .ok()
            .flatten()
            .and_then(|key| graph.owner.task(key).ok())
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
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();

        // Spawn 100 short-lived threads and exit them.
        for i in 0..100 {
            let tid = 1000 + i;
            entry.thread_spawned(41, tid, &mut || Ok(())).unwrap();
            // This fixture has no execution binding for its synthetic row.
            // Remove it in the graph instead of bypassing production custody.
            runtime
                .graph
                .lock()
                .owner
                .task_mut(key)
                .unwrap()
                .remove_thread(tid);
        }

        drop(entry);
        let graph = runtime.graph.lock();
        let t = graph.owner.task(key).unwrap();
        // The list must stay bounded to just the leader thread.
        assert_eq!(t.threads.threads.len(), 1);
        assert!(!t.has_thread(1050));
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
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
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
            entry.capset(41, caps),
            Err(carrick_personality_linux::identity::EPERM)
        );
        // capset on negative pid must fail with EPERM
        assert_eq!(
            entry.capset(-1, caps),
            Err(carrick_personality_linux::identity::EPERM)
        );
        // capset on own tid 42 and pid 0 must succeed
        assert_eq!(entry.capset(42, caps), Ok(()));
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();
        use carrick_personality_linux::identity::ProcessIdentityVenue;

        let parent_key = TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
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
        let child_pid = entry
            .fork_owned(ProcessForkChildTid::NONE)
            .expect("fork child succeeds") as i32;
        drop(entry);

        zone.requeue_preempted(slot, parent_record.id);
        let child_key = {
            let graph = runtime.graph.lock();
            graph
                .owner
                .namespace_key(graph.root_key, child_pid as u32)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task(key).ok())
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
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
        let child_pid = entry
            .fork_owned(ProcessForkChildTid::NONE)
            .expect("fork child succeeds") as u32;
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
            let peer = graph
                .owner
                .namespace_key(graph.root_key, child_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
                .unwrap();
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
                    execution: carrick_core_abi::entry::EntryGeneration::from_raw(12),
                    uid_credit: 1,
                },
            )
            .unwrap();
        child_page
            .bind_control_address(peer_entry, &child_controls[2] as *const _ as u64)
            .unwrap();
        child_controls[2]
            .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, peer_entry)
            .unwrap();
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
                c.fsuid = carrick_personality_linux::identity::TaskUid::new(2000);
                c.fsgid = carrick_personality_linux::identity::TaskGid::new(2000);
                Ok(())
            })
            .unwrap();
        {
            let mut graph = runtime.graph.lock();
            let peer = graph
                .owner
                .namespace_key(graph.root_key, child_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
                .unwrap();
            for tid in [child_pid, 987] {
                let c = peer.credentials_for_mut(tid).unwrap();
                c.ruid = carrick_personality_linux::identity::TaskUid::new(2000);
                c.euid = c.ruid;
                c.suid = c.ruid;
                c.rgid = carrick_personality_linux::identity::TaskGid::new(2000);
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
        frame.x[8] = carrick_syscall_abi::nr::GET_ROBUST_LIST.raw();
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
                carrick_syscall_abi::nr::GET_ROBUST_LIST.raw(),
                u64::MAX,
                &mut pending
            ),
            carrick_personality_linux::dispatch::CompletionRoute::WithWork
        );
        drop(pending);
        assert_eq!(
            task.linux.take_served_boundary(),
            Some(carrick_el1_abi::ServedBoundary::Completed)
        );
        assert_eq!(task.linux.take_served_boundary(), None);
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
                .namespace_key(graph.root_key, child_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
                .unwrap()
                .dumpable = 0;
        }
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            let peer = graph
                .owner
                .namespace_key(graph.root_key, child_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
                .unwrap();
            peer.dumpable = 1;
            peer.credentials_for_mut(987).unwrap().cap_permitted =
                carrick_personality_linux::identity::LinuxCapabilitySet::CAP_SETUID;
        }
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            graph
                .owner
                .namespace_key(graph.root_key, child_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
                .unwrap()
                .credentials_for_mut(987)
                .unwrap()
                .cap_permitted = carrick_personality_linux::identity::LinuxCapabilitySet::empty();
        }
        // A matching real uid cannot bypass mismatched filesystem credentials.
        entry
            .update_calling_creds(&mut |c| {
                c.ruid = carrick_personality_linux::identity::TaskUid::new(2000);
                c.rgid = carrick_personality_linux::identity::TaskGid::new(2000);
                c.fsuid = carrick_personality_linux::identity::TaskUid::new(1000);
                c.fsgid = carrick_personality_linux::identity::TaskGid::new(1000);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            entry.read_robust_list(987, &mut |_, _| Some((0xcafe, 24))),
            Err(carrick_personality_linux::identity::EPERM)
        );
        {
            let mut graph = runtime.graph.lock();
            let peer = graph
                .owner
                .namespace_key(graph.root_key, child_pid)
                .ok()
                .flatten()
                .and_then(|key| graph.owner.task_mut(key).ok())
                .unwrap();
            *peer.credentials_for_mut(child_pid).unwrap() =
                carrick_personality_linux::identity::TaskCredentials::ROOT;
        }
        entry
            .update_calling_creds(&mut |c| {
                c.cap_effective =
                    carrick_personality_linux::identity::LinuxCapabilitySet::CAP_SETUID;
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
                c.cap_effective =
                    carrick_personality_linux::identity::LinuxCapabilitySet::CAP_SYS_PTRACE;
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
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
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

    #[test]
    fn test_lock_order_graph_and_ipc_never_nested() {
        // Documented lock order invariant (N1):
        // Rule: Graph lock and IpcNamespace lock must NEVER be held concurrently.
        // Specifically:
        // 1. exit_owned() clones Arc<SpinLock<IpcNamespace>> out of Graph and drops the Graph guard
        //    before locking IpcNamespace to call exit_process(pid).
        // 2. msgsnd, msgrcv, and semop acquire IpcNamespace lock without holding Graph lock.
        //    Furthermore, get_or_create_channel, prune_ipc_channel, and wake_ipc_channel access
        //    ipc_channels directly on NativeProcessRuntime, so they never acquire Graph lock.
        // 3. Neither lock may be nested within the other on any execution path.
        let ipc = Arc::new(SpinLock::new(IpcNamespace::default()));
        let channels = Arc::new(SpinLock::new(Vec::<(u64, Arc<WaitChannel>)>::new()));
        let _g = ipc.lock();
        let _c = channels.lock();
    }

    #[test]
    fn test_blocked_ipc_returns_eintr_on_signal() {
        for operation in 0..4 {
            blocked_ipc_signal_contract(operation, false, false);
        }
    }
    #[test]
    fn admitted_ingress_record_interrupts_native_ipc_wait() {
        blocked_ipc_signal_contract(0, false, true);
    }
    #[test]
    fn bucket_contention_msgrcv() {
        blocked_ipc_signal_contract(0, true, false);
    }
    #[test]
    fn bucket_contention_semtimedop() {
        blocked_ipc_signal_contract(3, true, false);
    }
    #[test]
    fn arm_timed_semop_expires_at_shared_counter_deadline() {
        blocked_ipc_signal_contract(4, false, false);
    }
    #[test]
    fn msgrcv_resume_rejects_overflowing_msgp_and_restores_message() {
        blocked_ipc_signal_contract(5, false, false);
        blocked_ipc_signal_contract(7, false, false);
    }
    #[test]
    fn failed_ipc_enqueue_returns_timer_admission() {
        blocked_ipc_signal_contract(6, false, false);
    }
    fn blocked_ipc_signal_contract(operation: u8, contended: bool, external: bool) {
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
        let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
        let runtime = Arc::new(
            NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(
                source,
                &task,
                &page,
                &control,
                address,
                address,
                words(address),
            )
            .unwrap(),
        );
        if external {
            registry
                .register_root(runtime.clone(), source, &task, address)
                .unwrap();
        }
        assert_eq!(page.live(), 1);
        let mut service = Physical {
            zone: &zone,
            page: &child_page,
            controls: &*child_controls,
            copies: Vec::new(),
            tid_words: BTreeMap::new(),
            tid_wakes: 0,
            tid_writes: Vec::new(),
            refuse_copy: false,
            child_copy_error: None,
            on_signal_clock: None,
        };
        use carrick_personality_linux::ipc::{IpcOutcome, ProcessIpcVenue};
        use carrick_personality_linux::signal::{
            ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
        };
        let mut entry = if external {
            runtime
                .enter_registered(
                    registry,
                    source,
                    &task,
                    address,
                    words(address),
                    &mut service,
                )
                .unwrap()
        } else {
            runtime
                .enter(source, &task, words(address), &mut service)
                .unwrap()
        };
        let queue = entry.msgget(0, 0o600).unwrap();
        let sem = entry.semget(0, 1, 0o600).unwrap();
        let initial_timer_nodes = zone.timer_node_count();
        let waiting = core::sync::atomic::AtomicBool::new(false);
        let probe = |attempt| {
            if attempt == LOCK_SPINS {
                waiting.store(true, Ordering::Release);
            }
        };
        let guards = contended.then(|| {
            (0..carrick_sched_core::ZONE_BUCKETS)
                .map(|bucket| zone.lock(bucket, &BoundedSpin(0)).unwrap())
                .collect::<Vec<_>>()
        });
        entry.publication_wait_probe = Some(&probe);
        release_bucket_when_publisher_waits(guards, &waiting, || match operation {
            0 | 5 | 7 => {
                let msgp = match operation {
                    5 => UserVa::new(u64::MAX - 3),
                    7 => UserVa::new(carrick_guest_arch::USER_CEILING - 4),
                    _ => UserVa::new(0),
                };
                let result = entry.msgrcv(queue, msgp, 0, 0, 8);
                assert!(
                    matches!(result, Ok((IpcOutcome::Suspended, None))),
                    "msgrcv: {result:?}"
                );
            }
            1 => {
                let mut ds = carrick_syscall_abi::ipc::LinuxMsqidDs::default();
                entry
                    .msgctl(queue, carrick_syscall_abi::ipc::IPC_STAT, Some(&mut ds))
                    .unwrap();
                ds.msg_qbytes = 1;
                entry
                    .msgctl(queue, carrick_syscall_abi::ipc::IPC_SET, Some(&mut ds))
                    .unwrap();
                assert!(matches!(
                    entry.msgsnd(queue, 1, &[1], 0),
                    Ok(IpcOutcome::Returned(_))
                ));
                assert!(matches!(
                    entry.msgsnd(queue, 2, &[2], 0),
                    Ok(IpcOutcome::Suspended)
                ));
            }
            6 => {
                let guard = zone
                    .lock(
                        ZoneTables::<ParkedContextWords>::bucket_of_with_context(1, 0x7000),
                        &BoundedSpin(0),
                    )
                    .unwrap();
                let record = entry.record.id;
                let sequence = zone.next_seq(record);
                for index in 0..(carrick_sched_core::ZONE_ENTRIES - 1) {
                    zone.enqueue(&guard, record, sequence, 1, 0x7000, u32::MAX, index as u32)
                        .unwrap();
                }
                drop(guard);
                let ops = [carrick_personality_linux::ipc::LinuxSembuf {
                    sem_num: 0,
                    sem_op: -1,
                    sem_flg: 0,
                }];
                assert!(matches!(
                    entry.semop(sem, &ops, Some(core::time::Duration::from_nanos(1))),
                    Err(error) if error == carrick_syscall_abi::LINUX_EAGAIN.guest_retval()
                ));
            }
            _ => {
                let ops = [carrick_personality_linux::ipc::LinuxSembuf {
                    sem_num: 0,
                    sem_op: -1,
                    sem_flg: 0,
                }];
                let timeout = match operation {
                    3 => Some(core::time::Duration::from_secs(1)),
                    4 => Some(core::time::Duration::from_nanos(1)),
                    _ => None,
                };
                let result = entry.semop(sem, &ops, timeout);
                assert!(
                    matches!(result, Ok(IpcOutcome::Suspended)),
                    "semop: {result:?}"
                );
                assert_eq!(entry.semctl_getncnt(sem, 0), Ok(1));
            }
        });
        entry.publication_wait_probe = None;
        if operation == 6 {
            assert_eq!(zone.timer_node_count(), initial_timer_nodes);
            assert_eq!(runtime.graph.lock().pending.len(), 0);
            assert_eq!(entry.semctl_getncnt(sem, 0), Ok(0));
            return;
        }
        if contended {
            assert!(
                waiting.load(Ordering::Acquire),
                "IPC must reach the held bucket"
            );
        }
        assert_eq!(
            runtime.graph.lock().pending.len(),
            1,
            "one owned enrollment"
        );
        assert!(entry.take_handoff_receipt().is_some());
        assert!(zone.slot(slot).current().is_none());
        if operation == 4 {
            assert_eq!(zone.timer_deadline(slot), Some(1001));
            assert_eq!(zone.expire_timer(slot, 1001, (-11_i64) as u64), Ok(true));
            let selected = zone.switch_in_full(slot).expect("timer must wake semop");
            assert_eq!(zone.record_ref(selected.record), entry.record);
            assert!(
                matches!(entry.resume_pending_wait(), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == carrick_syscall_abi::LINUX_EAGAIN.guest_retval())
            );
            assert_eq!(entry.semctl_getncnt(sem, 0), Ok(0));
            assert!(zone.timer_owner(slot).is_none());
            return;
        }
        if operation == 5 || operation == 7 {
            assert!(matches!(
                entry.msgsnd(queue, 1, &[7], 0),
                Ok(IpcOutcome::Returned(_))
            ));
            let selected = zone.switch_in_full(slot).expect("message must wake msgrcv");
            assert_eq!(zone.record_ref(selected.record), entry.record);
            assert!(
                matches!(entry.resume_pending_wait(), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == carrick_syscall_abi::LINUX_EFAULT.guest_retval())
            );
            assert!(
                matches!(entry.msgrcv(queue, UserVa::new(0), 0, carrick_syscall_abi::ipc::IPC_NOWAIT, 8), Ok((IpcOutcome::Returned(_), Some((_, 1, data)))) if data == [7])
            );
            return;
        }
        // Publish through the same signal owner while execution capacity is
        // released, using the external transport for the SIGINT case.
        if external {
            let binding = crate::personality::common_entry::execution_binding(&task);
            let queue = carrick_el1_abi::SharedSignalIngressQueue::new();
            queue
                .admit(carrick_el1_abi::ExternalSignalRecord::new(
                    carrick_core_abi::EntryEventIdentity::from_binding(binding),
                    binding,
                    entry.record,
                    carrick_el1_abi::SignalEventGeneration::new(NonZeroU64::MIN),
                    carrick_signal_core::policy::Signal::from_number(2).unwrap(),
                    carrick_el1_abi::ExternalSignalSource::Terminal,
                ))
                .unwrap();
            assert_eq!(
                registry
                    .drain_external_ingress(&zone, &queue, slot, entry.service)
                    .unwrap(),
                1
            );
        } else {
            entry
                .kill(
                    SignalProcessSelector::from_abi(41),
                    SignalRequest::from_abi(10).unwrap(),
                    SignalInfo::Generated(None),
                )
                .unwrap();
        }
        let selected = zone
            .switch_in_full(slot)
            .expect("signal must wake the owned IPC continuation");
        assert_eq!(zone.record_ref(selected.record), entry.record);
        assert!(
            matches!(entry.resume_pending_wait(), Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == carrick_syscall_abi::LINUX_EINTR.guest_retval())
        );
        assert!(!runtime.graph.lock().pending.contains_key(&entry.key));
        if operation >= 2 {
            assert_eq!(entry.semctl_getncnt(sem, 0), Ok(0));
        }
        assert!(zone.timer_owner(slot).is_none());
        if operation == 1 {
            assert!(
                matches!(entry.msgrcv(queue, UserVa::new(0), 0, carrick_syscall_abi::ipc::IPC_NOWAIT, 8),
                Ok((IpcOutcome::Returned(_), Some((_, 1, data)))) if data == [1])
            );
        }
    }

    struct FaultyPhysical<'a> {
        zone: &'a ZoneTables<ParkedContextWords>,
        child_pages: &'a [ThreadLifecyclePage],
        child_controls: &'a [[ThreadControlSlot; 9]],
        active_loan: Option<usize>,
        next_page: usize,
        loan_in_flight: bool,
        abort_count: usize,
        fail_context: bool,
        fail_fd_table: bool,
        fail_commit: bool,
    }

    impl<'a> NativeProcessService<'a, ParkedContextWords> for FaultyPhysical<'a> {
        type Mm = AddressContext<RootGpa>;
        type PreparedMm = AddressContext<RootGpa>;
        type Born = AddressContext<RootGpa>;

        fn prepare_mm(
            &mut self,
            _: &Self::Mm,
            _: ParkedContextWords,
            child: MmGeneration,
        ) -> Result<Self::PreparedMm, NativeProcessError> {
            assert!(
                !self.loan_in_flight,
                "refusing loan: previous loan is still pending on this vCPU"
            );
            let address = AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(
                    0x2000 + (self.next_page as u64) * 0x1000,
                ))
                .unwrap(),
                mm: child,
                generation: ContextGeneration::new(NonZeroU64::MIN),
            };
            self.zone
                .spaces
                .publish_closed(child.raw().get(), address.root.address().raw(), 0)
                .ok_or(NativeProcessError::Exhausted)?;
            self.loan_in_flight = true;
            let idx = self.next_page;
            self.next_page += 1;
            self.active_loan = Some(idx);
            Ok(address)
        }

        fn prepared_mm(&self, p: &Self::PreparedMm) -> Self::Mm {
            *p
        }

        fn prepared_context(&self, p: &Self::PreparedMm) -> AddressContext<RootGpa> {
            if self.fail_context {
                let mut bad = *p;
                bad.mm = MmGeneration::new(NonZeroU64::new(bad.mm.raw().get() + 999).unwrap());
                return bad;
            }
            *p
        }

        fn child_lifecycle(&self, _: &Self::PreparedMm) -> NativeLifecycleResources<'a> {
            let idx = self.active_loan.expect("active loan for child_lifecycle");
            NativeLifecycleResources {
                page: &self.child_pages[idx],
                controls: &self.child_controls[idx],
            }
        }

        fn commit_mm(
            &mut self,
            p: Self::PreparedMm,
        ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
            if self.fail_commit {
                return Err((NativeProcessError::Busy, p));
            }
            Ok(p)
        }

        fn abort_mm(
            &mut self,
            p: Self::PreparedMm,
        ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
            assert!(
                self.loan_in_flight,
                "abort_mm called without in-flight loan"
            );
            if let Some(index) = self.active_loan {
                assert!(
                    self.child_controls[index]
                        .iter()
                        .all(|control| !control.graph_referenced()),
                    "returning a fork loan must not leave control custody alive"
                );
            }
            self.loan_in_flight = false;
            self.abort_count += 1;
            self.active_loan = None;
            self.zone
                .spaces
                .free(self.zone.spaces.find(p.mm.raw().get()).unwrap());
            Ok(())
        }

        fn settle_mm(&mut self, b: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
            assert!(
                self.loan_in_flight,
                "settle_mm called without in-flight loan"
            );
            self.loan_in_flight = false;
            self.active_loan = None;
            self.zone
                .spaces
                .open(self.zone.spaces.find(b.mm.raw().get()).unwrap());
            Ok(())
        }

        fn copy_status(
            &mut self,
            _: &Self::Mm,
            _: UserVa,
            _: LinuxWaitStatus,
        ) -> Result<(), NativeProcessError> {
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

        fn retire_mm(&mut self, mm: Self::Mm) {
            let index = (mm.root.address().raw() - 0x2000) as usize / 0x1000;
            assert!(
                self.child_controls[index]
                    .iter()
                    .all(|control| !control.graph_referenced()),
                "retiring a fork child MM must not leave control custody alive on its loaned stock"
            );
            for control in &self.child_controls[index] {
                control
                    .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
                    .expect("unreferenced control resets through interior mutability");
            }
        }

        fn wake_effects(&mut self, _: WakeEffects) {}
        fn request_ingress_producer_boundary(&mut self) {}

        fn fork_fd_table(&mut self, _: u64, _: u64) -> Result<(), NativeProcessError> {
            if self.fail_fd_table {
                return Err(NativeProcessError::Exhausted);
            }
            Ok(())
        }
    }

    #[test]
    fn fork_failure_injection_after_prepare_loaned_cleans_up_and_subsequent_fork_succeeds() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
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
        let child_pages: Vec<_> = (0..16).map(|_| ThreadLifecyclePage::new()).collect();
        let child_controls: Vec<_> = (0..16)
            .map(|_| core::array::from_fn(|_| ThreadControlSlot::new()))
            .collect();
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

        let mut service = FaultyPhysical {
            zone: &zone,
            child_pages: &child_pages,
            child_controls: &child_controls,
            active_loan: None,
            next_page: 0,
            loan_in_flight: false,
            abort_count: 0,
            fail_context: false,
            fail_fd_table: false,
            fail_commit: false,
        };

        let mut entry = runtime
            .enter(source, &task, words(address), &mut service)
            .unwrap();

        // 1. Injected failure at metadata validation (address.mm mismatch)
        entry.service.fail_context = true;
        let outcome1 = entry.fork(ProcessForkChildTid::NONE);
        assert!(matches!(
            outcome1,
            LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::Stale.errno()
        ));
        assert_eq!(entry.service.abort_count, 1);
        assert!(!entry.service.loan_in_flight);
        entry.service.fail_context = false;

        // Next fork succeeds!
        let outcome2 = entry.fork(ProcessForkChildTid::NONE);
        let LifecycleOutcome::Returned { result: pid1, .. } = outcome2 else {
            panic!("expected fork success after metadata validation recovery");
        };
        assert_eq!(pid1.raw(), 43);
        assert_eq!(entry.service.abort_count, 1);
        assert!(!entry.service.loan_in_flight);

        // 2. Injected failure at fork_fd_table
        entry.service.fail_fd_table = true;
        let outcome3 = entry.fork(ProcessForkChildTid::NONE);
        assert!(matches!(
            outcome3,
            LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::Exhausted.errno()
        ));
        assert_eq!(entry.service.abort_count, 2);
        assert!(!entry.service.loan_in_flight);
        entry.service.fail_fd_table = false;

        // Next fork succeeds!
        let outcome4 = entry.fork(ProcessForkChildTid::NONE);
        let LifecycleOutcome::Returned { result: pid2, .. } = outcome4 else {
            panic!("expected fork success after fd_table recovery");
        };
        assert_eq!(pid2.raw(), 45);
        assert_eq!(entry.service.abort_count, 2);
        assert!(!entry.service.loan_in_flight);

        // 3. Injected failure at commit_mm
        entry.service.fail_commit = true;
        let outcome5 = entry.fork(ProcessForkChildTid::NONE);
        assert!(matches!(
            outcome5,
            LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::Busy.errno()
        ));
        assert_eq!(entry.service.abort_count, 3);
        assert!(!entry.service.loan_in_flight);
        entry.service.fail_commit = false;

        // Next fork succeeds!
        let outcome6 = entry.fork(ProcessForkChildTid::NONE);
        let LifecycleOutcome::Returned { result: pid3, .. } = outcome6 else {
            panic!("expected fork success after commit recovery");
        };
        assert_eq!(pid3.raw(), 47);
        assert_eq!(entry.service.abort_count, 3);
        assert!(!entry.service.loan_in_flight);

        // 4. Injected failure at alloc_record exhaustion
        let mut filled_records = Vec::new();
        while let Ok(r) = zone.alloc_record(ThreadIdentity {
            tid: 900 + filled_records.len() as u64,
            serial: 900,
            mm: 1,
            file_table: 5,
            generation: 11,
            affinity: 1,
            lifecycle_page: &*page as *const _ as u64,
            control_slot: &*control as *const _ as u64,
        }) {
            filled_records.push(r);
        }
        assert!(!filled_records.is_empty());

        let outcome7 = entry.fork(ProcessForkChildTid::NONE);
        assert!(matches!(
            outcome7,
            LifecycleOutcome::Returned { result, .. } if result.raw() == NativeProcessError::Exhausted.errno()
        ));
        assert_eq!(entry.service.abort_count, 4);
        assert!(!entry.service.loan_in_flight);

        // Free one record so alloc_record can succeed
        zone.free_record(filled_records.pop().unwrap());

        // Next fork succeeds!
        let outcome8 = entry.fork(ProcessForkChildTid::NONE);
        let LifecycleOutcome::Returned { result: pid4, .. } = outcome8 else {
            panic!("expected fork success after alloc_record exhaustion recovery");
        };
        assert_eq!(pid4.raw(), 49);
        assert_eq!(entry.service.abort_count, 4);
        assert!(!entry.service.loan_in_flight);

        for r in filled_records {
            zone.free_record(r);
        }
    }
}
