//! Linux syscall dispatch and completion mapping.
use super::{file, inotify, ipc, lifecycle, sched};
use crate::fault::dispatch_fault;
use crate::memory;
use carrick_el1_abi::{
    Action, Counters, CurrentTask, DELEGATED_STATE_GUEST, DelegatedFile, DelegatedInotify,
    DelegatedOpenFile, EL1_GUEST_LOCK_SPINS, FdMapSlot, InotifyNameCache, MAX_DELEGATED_FILES,
    MAX_DELEGATED_MARKS_PER_FILE, MAX_ZONE_OPEN_FILES, SlotId, TrapFrame, ZoneTables,
    fd_map_lookup,
};
#[cfg(target_os = "none")]
use carrick_el1_abi::{
    EL1_CURRENT_TASKS_BASE, EL1_FD_MAP_BASE, EL1_INOTIFY_TABLE_BASE, EL1_NAME_CACHE_BASE,
    EL1_OBJECT_TABLE_BASE, EL1_OPEN_FILE_TABLE_BASE, EL1_STACK_SLOTS, EL1_ZONE_BASE,
    FD_MAP_CAPACITY, MAX_DELEGATED_INOTIFY,
};
use carrick_guest_arch::SyscallFrame;
use carrick_personality_linux::abi::entry::{LinuxTaskState, SyscallResult};
use carrick_personality_linux::dispatch::{EntryCounters, LifecycleWorkCounters};
use carrick_personality_linux::dispatch::{FamilyCompletion, PendingFamilies};
#[cfg(target_os = "none")]
use carrick_personality_linux::pending_anonymous::{DelegatedStep, PermissionStep, RetirementStep};
use carrick_personality_linux::pending_file::PendingFileVenue;
use core::sync::atomic::Ordering;

/// ARM frame access is retained for scheduler/IPC park leaves that have not
/// yet acquired an ISA-neutral saved-context contract.
pub trait GuestDispatchFrame: SyscallFrame {
    fn arm_frame(&mut self) -> Option<&mut TrapFrame>;
    fn arm_frame_ref(&self) -> Option<&TrapFrame>;
    fn arm_scheduler(&self) -> bool;
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64>;
    /// Distinguish an ISA-only refusal from a family or venue refusal.
    fn record_isa_unsupported_forward(&self) {}
}

impl GuestDispatchFrame for TrapFrame {
    fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
        Some(self)
    }
    fn arm_scheduler(&self) -> bool {
        true
    }
    fn arm_frame_ref(&self) -> Option<&TrapFrame> {
        Some(self)
    }
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
        None
    }
}

/// T2's SVC integration point. A Work result is an owned continuation, not a
/// completed syscall and not permission to enter the host syscall dispatcher.
pub enum AnonymousReservationRoute {
    Action(Action),
    Work(memory::PendingReservationSyscall),
    Unavailable(memory::reservations::Refusal),
}

pub fn dispatch_anonymous_with_reservations(
    frame: &mut TrapFrame,
    counters: &Counters,
    current: &CurrentTask,
    model: &mut memory::reservations::Reservations<'_>,
) -> AnonymousReservationRoute {
    use carrick_personality_linux::dispatch::ReservationDecision;
    let decision = match memory::decide_anonymous_syscall(frame, current, model) {
        memory::ReservationDisposition::Forward => ReservationDecision::Forward,
        memory::ReservationDisposition::Return(value) => ReservationDecision::Return(value),
        memory::ReservationDisposition::Work(work) => ReservationDecision::Work(work),
        memory::ReservationDisposition::Unavailable(reason) => {
            ReservationDecision::Unavailable(reason)
        }
    };
    let entry = EntryCounters {
        served: &counters.served,
        forwarded: &counters.forwarded,
    };
    let route = carrick_personality_linux::dispatch::dispatch_anonymous(decision, |served| {
        if served {
            entry.served(frame.x[8]);
        } else {
            entry.forwarded(frame.x[8]);
        }
    });
    match route {
        ReservationDecision::Forward => AnonymousReservationRoute::Action(Action::Forward),
        ReservationDecision::Return(value) => {
            frame.x[0] = value as u64;
            AnonymousReservationRoute::Action(Action::Served)
        }
        ReservationDecision::Work(work) => AnonymousReservationRoute::Work(work),
        ReservationDecision::Unavailable(reason) => AnonymousReservationRoute::Unavailable(reason),
    }
}

/// The shared-record layout this image was built against; the image header
/// points at it and the host refuses an image whose value differs
/// (`carrick_el1_abi::check_image_abi`).
#[unsafe(no_mangle)]
#[used]
pub static CARRICK_EL1_ABI_HASH: u64 = carrick_el1_abi::EL1_ABI_LAYOUT_HASH;

/// Dispatch an in-guest Linux syscall at EL1.
pub fn dispatch_syscall(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks =
            unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
        let fd_map = unsafe { &*(EL1_FD_MAP_BASE as *const [FdMapSlot; FD_MAP_CAPACITY]) };
        let object_table =
            unsafe { &*(EL1_OBJECT_TABLE_BASE as *const [DelegatedFile; MAX_DELEGATED_FILES]) };
        let open_table = unsafe {
            &*(EL1_OPEN_FILE_TABLE_BASE as *const [DelegatedOpenFile; MAX_ZONE_OPEN_FILES])
        };
        let inotify_table = unsafe {
            &*(EL1_INOTIFY_TABLE_BASE as *const [DelegatedInotify; MAX_DELEGATED_INOTIFY])
        };
        let name_cache = unsafe { &*(EL1_NAME_CACHE_BASE as *const InotifyNameCache) };
        let zone = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
        dispatch_syscall_with_ipc(
            frame,
            counters,
            current_tasks,
            fd_map,
            object_table,
            open_table,
            inotify_table,
            name_cache,
            Some(Zone {
                tables: zone,
                cpu: &mut sched::HardwareCpu,
                user: &sched::HardwareUserWord,
            }),
            ipc::guest_venue(frame.slot as u32).as_ref(),
            |handle| carrick_el1_abi::delegated_file_cache_va(handle) as *mut u8,
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        let nr = frame.x[8] as usize;
        if nr < 512 {
            counters.forwarded[nr].fetch_add(1, Ordering::Relaxed);
        }
        Action::Forward
    }
}

/// Handle an interrupt taken while EL0 ran (the vector's EL0 IRQ hook marks
/// such a frame with `esr == 0`). `Served` returns to EL0, possibly as
/// another thread; `Forward` leaves through the host at this EL0 boundary.
pub fn dispatch_irq(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks =
            unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
        let zone = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
        dispatch_irq_with_regions(
            frame,
            counters,
            current_tasks,
            Zone {
                tables: zone,
                cpu: &mut sched::HardwareCpu,
                user: &sched::HardwareUserWord,
            },
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (frame, counters);
        Action::Forward
    }
}

/// Unified entry dispatch (interrupts, lower-EL data aborts, and syscalls).
pub fn dispatch_entry(frame: &mut TrapFrame, counters: &Counters) -> Action {
    if frame.esr == 0 {
        return dispatch_irq(frame, counters);
    }
    if matches!((frame.esr >> 26) & 0x3f, 0x20 | 0x24) {
        return dispatch_fault(frame, counters);
    }
    dispatch_syscall(frame, counters)
}

/// [`dispatch_irq`] with explicitly supplied tables (EL1 and host tests).
pub fn dispatch_irq_with_regions<C, U>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    zone: Zone<'_, C, U>,
) -> Action
where
    C: sched::ThreadCpu,
    U: sched::UserWord,
{
    let (Some(task), Some(slot)) = (
        current_tasks.get(frame.slot as usize),
        SlotId::from_index(frame.slot as usize),
    ) else {
        return Action::Forward;
    };
    let mut sched = sched::Sched {
        handoff: None,
        zone: zone.tables,
        slot,
        task,
        cpu: zone.cpu,
        user: zone.user,
        counters,
    };
    // The idle entry: the host started this vCPU in the scheduler with no
    // thread (a frame with no EL0 return address, which an interrupt taken
    // at EL0 never has).
    if frame.elr == 0 {
        return sched.serve_idle_entry(frame);
    }
    sched.serve_irq(frame)
}

/// The in-guest scheduler's tables and the CPU and user-memory access an
/// in-guest switch uses ([`sched`]).
pub struct Zone<'a, C: sched::ThreadCpu, U: sched::UserWord> {
    pub tables: &'a ZoneTables,
    pub cpu: &'a mut C,
    pub user: &'a U,
}

/// Dispatch syscall with explicitly supplied tables (used at EL1 and for host tests).
#[allow(clippy::too_many_arguments)]
pub fn dispatch_syscall_with_regions<F, C, U>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    open_table: &[DelegatedOpenFile],
    inotify_table: &[DelegatedInotify],
    name_cache: &InotifyNameCache,
    zone: Option<Zone<'_, C, U>>,
    cache_lookup: F,
) -> Action
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
{
    dispatch_syscall_with_ipc(
        frame,
        counters,
        current_tasks,
        fd_map,
        object_table,
        open_table,
        inotify_table,
        name_cache,
        zone,
        None,
        cache_lookup,
    )
}

/// [`dispatch_syscall_with_regions`] with the shared IPC authority, when
/// this venue has one: read/write on pipes and eventfds are served in EL1.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_syscall_with_ipc<F, C, U>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    open_table: &[DelegatedOpenFile],
    inotify_table: &[DelegatedInotify],
    name_cache: &InotifyNameCache,
    zone: Option<Zone<'_, C, U>>,
    ipc: Option<&ipc::IpcVenue<'_>>,
    cache_lookup: F,
) -> Action
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
{
    dispatch_syscall_with_lifecycle(
        frame,
        counters,
        current_tasks,
        fd_map,
        object_table,
        open_table,
        inotify_table,
        name_cache,
        zone,
        ipc,
        lifecycle::guest_venue(),
        cache_lookup,
    )
}

/// [`dispatch_syscall_with_ipc`] with the thread lifecycle state the host
/// published for this venue ([`lifecycle::LifecycleVenue`]): thread clone
/// and exit and the per-thread setup calls are served in EL1.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_syscall_with_lifecycle<'a, F, C, U, G>(
    frame: &'a mut G,
    counters: &'a Counters,
    current_tasks: &'a [CurrentTask],
    fd_map: &'a [FdMapSlot],
    object_table: &'a [DelegatedFile],
    open_table: &'a [DelegatedOpenFile],
    inotify_table: &'a [DelegatedInotify],
    name_cache: &'a InotifyNameCache,
    zone: Option<Zone<'a, C, U>>,
    ipc: Option<&'a ipc::IpcVenue<'a>>,
    lifecycle: Option<&'a dyn lifecycle::LifecycleVenue>,
    cache_lookup: F,
) -> Action
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
{
    let is_x86 = frame.arm_frame_ref().is_none();
    let ordinal = frame.canonical_ordinal().raw();
    let mut pending = El1PendingFamilies {
        handoff: None,
        #[cfg(test)]
        lifecycle_user: None,
        frame,
        counters,
        current_tasks,
        fd_map,
        object_table,
        open_table,
        inotify_table,
        name_cache,
        zone,
        ipc,
        lifecycle,
        cache_lookup,
    };
    let control = if cfg!(feature = "allocator-test-control") {
        carrick_el1_abi::SYS_CARRICK_EL1_CONTROL
    } else {
        u64::MAX
    };
    let route = if is_x86 {
        carrick_personality_linux::dispatch::dispatch_x86(ordinal, control, &mut pending)
    } else {
        carrick_personality_linux::dispatch::dispatch(ordinal, control, &mut pending)
    };
    match route {
        carrick_personality_linux::dispatch::CompletionRoute::Served => Action::Served,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork => Action::ServedWithWork,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended => Action::Idle,
        carrick_personality_linux::dispatch::CompletionRoute::Forward => Action::Forward,
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion => {
            invalid_completion()
        }
    }
}

/// A completed effect must never be forwarded for syscall replay when its
/// exact binding failed authentication. This is native fail-stop transport.
fn invalid_completion() -> ! {
    #[cfg(target_os = "none")]
    crate::substrate::sched::hw::fatal_entry_binding();
    #[cfg(not(target_os = "none"))]
    carrick_fatal::carrick_fatal!(
        "el1::entry_completion",
        "entry completion lost its exact execution binding"
    )
}

pub struct El1PendingFamilies<
    'a,
    F,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame = TrapFrame,
> {
    pub(super) handoff: Option<carrick_el1_abi::EntryHandoffReceipt>,
    #[cfg(test)]
    pub(super) lifecycle_user: Option<&'a mut dyn file::UserCopy>,
    pub(super) frame: &'a mut G,
    pub(super) counters: &'a Counters,
    pub(super) current_tasks: &'a [CurrentTask],
    pub(super) fd_map: &'a [FdMapSlot],
    pub(super) object_table: &'a [DelegatedFile],
    pub(super) open_table: &'a [DelegatedOpenFile],
    pub(super) inotify_table: &'a [DelegatedInotify],
    pub(super) name_cache: &'a InotifyNameCache,
    pub(super) zone: Option<Zone<'a, C, U>>,
    pub(super) ipc: Option<&'a ipc::IpcVenue<'a>>,
    pub(super) lifecycle: Option<&'a dyn lifecycle::LifecycleVenue>,
    pub(super) cache_lookup: F,
}
impl<'a, F: Fn(u32) -> *mut u8, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame>
    PendingFamilies<'a> for El1PendingFamilies<'a, F, C, U, G>
{
    fn take_handoff_receipt(&mut self) -> Option<carrick_el1_abi::EntryHandoffReceipt> {
        self.handoff.take()
    }
    fn binding(&self) -> Option<carrick_el1_abi::ExecutionBinding> {
        self.task().map(super::common_entry::execution_binding)
    }
    fn record_source(&self) -> Option<carrick_el1_abi::BornInZoneSource<'a>> {
        Some(carrick_el1_abi::BornInZoneSource {
            zone: self.zone.as_ref()?.tables,
            slot: self.frame.slot()?,
        })
    }
    #[cfg(target_os = "none")]
    fn anonymous_venue(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue> {
        Some(self)
    }
    fn file_venue(&mut self) -> Option<&mut dyn PendingFileVenue> {
        Some(self)
    }
    fn task_state(&self) -> Option<&LinuxTaskState> {
        self.task().map(|task| &task.linux)
    }
    fn entry_counters(&self) -> Option<EntryCounters<'_>> {
        Some(EntryCounters {
            served: &self.counters.served,
            forwarded: &self.counters.forwarded,
        })
    }
    fn read(&mut self) -> FamilyCompletion {
        self.ipc_transfer()
    }
    fn write(&mut self) -> FamilyCompletion {
        self.ipc_transfer()
    }
    fn epoll_wait(&mut self) -> FamilyCompletion {
        self.ipc_transfer()
    }
    fn original_argument0(&self) -> u64 {
        self.frame.argument(0).unwrap_or(0)
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame
            .set_result(carrick_guest_arch::NativeReturnWord(result.raw() as u64));
    }
    fn lifecycle_native(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::lifecycle::LifecycleNative<'a>> {
        self.lifecycle?;
        self.current_tasks.get(self.frame.task_index())?;
        Some(self)
    }
    fn futex(&mut self) -> FamilyCompletion {
        let Some(frame) = self.frame.arm_frame() else {
            self.frame.record_isa_unsupported_forward();
            return FamilyCompletion::Forward;
        };
        let counters = self.counters;
        let zone = &mut self.zone;
        let current_tasks = self.current_tasks;
        let slot = frame.slot as usize;
        let cur_task = current_tasks.get(slot);
        if let (Some(zone), Some(task), Some(zslot)) =
            (zone.as_mut(), cur_task, SlotId::from_index(slot))
        {
            let orig_x0 = frame.x[0];
            let mut sched = native_scheduler(zone, task, counters, zslot, &mut self.handoff);
            let disposition = sched
                .serve_futex(frame)
                .map_or(ipc::IpcServed::Forward, ipc::IpcServed::from);
            return carrick_personality_linux::dispatch::transfer_effect(
                &task.linux,
                orig_x0,
                frame.x[0] as i64,
                disposition,
            );
        }

        FamilyCompletion::Forward
    }
    #[cfg(feature = "allocator-test-control")]
    fn allocator_control(&mut self) -> FamilyCompletion {
        let Some(frame) = self.frame.arm_frame() else {
            self.frame.record_isa_unsupported_forward();
            return FamilyCompletion::Forward;
        };
        let counters = self.counters;
        let zone = &mut self.zone;
        let current_tasks = self.current_tasks;
        let slot = frame.slot as usize;
        let cur_task = current_tasks.get(slot);

        let orig_x0 = frame.x[0];
        #[cfg(target_os = "none")]
        let saved = *frame;
        // Consume the record-owned metadata wait before executing this
        // control transaction again; IPC cannot construct this token.
        if let (Some(zone), Some(task), Some(zslot)) =
            (zone.as_mut(), cur_task, SlotId::from_index(slot))
        {
            let sched = native_scheduler(zone, task, counters, zslot, &mut self.handoff);
            if let Ok(Some(operation)) = sched.take_object_operation()
                && operation.metadata_generation().is_none()
            {
                return FamilyCompletion::Handback;
            }
        }
        let res = match frame.x[0] {
            1 => crate::alloc::run_guest_allocator_test(frame.x[1], frame.x[2]),
            _ => 1,
        };
        if res == carrick_el1_abi::METADATA_GRANT_PENDING {
            #[cfg(target_os = "none")]
            if let (Some(zone), Some(task), Some(zslot)) =
                (zone.as_mut(), cur_task, SlotId::from_index(slot))
            {
                let mailbox = carrick_el1_abi::metadata_mailbox_guest();
                let generation = mailbox.request_generation();
                let mut sched = native_scheduler(zone, task, counters, zslot, &mut self.handoff);
                if let (Some(key), Some(operation), Some(resume)) = (
                    carrick_sched_core::object_wait::ObjectWaitKey::metadata_request(generation),
                    carrick_sched_core::object_wait::OperationToken::metadata_request(generation),
                    crate::substrate::sched::object_wait::OperationResumePc::new(
                        saved.elr.wrapping_sub(4),
                    ),
                ) && let Ok(snapshot) = sched.observe_object(key)
                    && matches!(
                        mailbox.state.load(Ordering::Acquire),
                        carrick_el1_abi::METADATA_MAILBOX_REQUESTED
                            | carrick_el1_abi::METADATA_MAILBOX_HOST_WORKING
                    )
                    && mailbox.request_generation() == generation
                    && let Ok(parked) =
                        sched.park_object(&saved, key, snapshot, resume, operation, None)
                {
                    let _ = sched.leave_after_object_park(parked);
                    return FamilyCompletion::AccountedSuspended;
                }
            }
        }
        frame.x[0] = res;
        carrick_personality_linux::dispatch::allocator_effect(
            cur_task.map(|task| &task.linux),
            orig_x0,
            SyscallResult::new(res as i64),
        )
    }

    fn resumes_operation(&self) -> bool {
        self.zone.as_ref().is_some_and(|zone| {
            self.frame
                .slot()
                .and_then(|slot| zone.tables.slot(slot).current())
                .is_some_and(|record| zone.tables.record(record).has_object_operation())
        })
    }
    fn ipc_available(&self) -> bool {
        self.ipc.is_some()
    }
    fn lifecycle_available(&self) -> bool {
        self.lifecycle.is_some()
    }
    fn lifecycle_work_counters(&self) -> Option<LifecycleWorkCounters<'_>> {
        Some(LifecycleWorkCounters {
            exit: &self.counters.lifecycle_declines
                [carrick_el1_abi::LifecycleDecline::ExitDispatchHostWork as usize],
            clone: &self.counters.lifecycle_declines
                [carrick_el1_abi::LifecycleDecline::CloneDispatchHostWork as usize],
        })
    }
    fn anonymous_declined_for_work(&self, _ordinal: u64) {
        #[cfg(target_os = "none")]
        if let (Some(zone), Some(task), Some(slot)) =
            (self.zone.as_ref(), self.task(), self.frame.slot())
            && memory::delegated_anonymous_root(
                _ordinal,
                task,
                crate::substrate::sched::object_wait::space_access(zone.tables, slot),
                memory::reservations::shared_guest(),
            )
            .is_some()
        {
            self.counters.anonymous_leaves
                [carrick_el1_abi::AnonymousLeave::PendingHostWork as usize]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[cfg(target_os = "none")]
impl<F: Fn(u32) -> *mut u8, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame>
    carrick_personality_linux::pending_anonymous::PendingAnonymousVenue
    for El1PendingFamilies<'_, F, C, U, G>
{
    fn original_argument0(&self) -> u64 {
        self.frame.argument(0).unwrap_or(0)
    }
    fn task_state(&self) -> Option<&LinuxTaskState> {
        self.task().map(|task| &task.linux)
    }
    fn delegated(&mut self) -> DelegatedStep {
        let (Some(zone), Some(task), Some(slot)) = (
            self.zone.as_ref(),
            self.current_tasks.get(self.frame.task_index()),
            self.frame.slot(),
        ) else {
            return DelegatedStep::NotDelegated;
        };
        let access = crate::substrate::sched::object_wait::space_access(zone.tables, slot);
        match memory::serve_delegated_anonymous(
            match self.frame.arm_frame() {
                Some(frame) => frame,
                None => {
                    self.frame.record_isa_unsupported_forward();
                    return DelegatedStep::NotDelegated;
                }
            },
            self.counters,
            task,
            access,
            memory::reservations::shared_guest(),
            &mut memory::HardwareAnonymousEditor,
        ) {
            memory::DelegatedAnonymous::PreparedConflict => DelegatedStep::PreparedConflict,
            memory::DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            memory::DelegatedAnonymous::Served => {
                DelegatedStep::Served(SyscallResult::new(self.frame.result().0 as i64))
            }
            memory::DelegatedAnonymous::Forward => DelegatedStep::Forward,
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        let slot = self.frame.slot()?;
        let task = self.current_tasks.get(self.frame.task_index())?;
        let zone = self.zone.as_mut()?;
        let mut sched = native_scheduler(zone, task, self.counters, slot, &mut self.handoff);
        let served = super::mm_portal::park_prepared_edit(
            &mut sched,
            self.frame.arm_frame()?,
            memory::reservations::shared_guest(),
        )?;
        Some(
            carrick_personality_linux::dispatch::accounted_scheduler_effect(
                served,
                self.frame.result().0 as i64,
            ),
        )
    }
    fn permission(&mut self) -> PermissionStep {
        let (Some(zone), Some(slot)) = (self.zone.as_ref(), self.frame.slot()) else {
            return PermissionStep::Forward;
        };
        let access = crate::substrate::sched::object_wait::space_access(zone.tables, slot);
        match memory::try_serve_mprotect(
            match self.frame.arm_frame() {
                Some(frame) => frame,
                None => {
                    self.frame.record_isa_unsupported_forward();
                    return PermissionStep::Forward;
                }
            },
            self.current_tasks,
            access,
            &mut memory::HardwareAnonymousPermissionEditor,
        ) {
            memory::MprotectDisposition::Forward => PermissionStep::Forward,
            memory::MprotectDisposition::Return(result) => {
                PermissionStep::Return(SyscallResult::new(result))
            }
            memory::MprotectDisposition::ReturnWithWork => PermissionStep::CommitOwed,
        }
    }
    fn retirement(&mut self) -> RetirementStep {
        let (Some(zone), Some(slot)) = (self.zone.as_ref(), self.frame.slot()) else {
            return RetirementStep::Forward;
        };
        let access = crate::substrate::sched::object_wait::space_access(zone.tables, slot);
        match memory::try_serve_munmap(
            match self.frame.arm_frame() {
                Some(frame) => frame,
                None => {
                    self.frame.record_isa_unsupported_forward();
                    return RetirementStep::Forward;
                }
            },
            self.current_tasks,
            access,
            &mut memory::HardwareAnonymousRetirementEditor,
        ) {
            memory::MunmapDisposition::Forward => RetirementStep::Forward,
            memory::MunmapDisposition::Return(result) => {
                RetirementStep::Return(SyscallResult::new(result))
            }
            memory::MunmapDisposition::Retired => RetirementStep::Retired,
        }
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame
            .set_result(carrick_guest_arch::NativeReturnWord(result.raw() as u64));
    }
}

pub(super) fn native_scheduler<'s, C: sched::ThreadCpu, U: sched::UserWord>(
    zone: &'s mut Zone<'_, C, U>,
    task: &'s CurrentTask,
    counters: &'s Counters,
    slot: SlotId,
    handoff: &'s mut Option<carrick_el1_abi::EntryHandoffReceipt>,
) -> sched::Sched<'s, C, U> {
    sched::Sched {
        handoff: Some(handoff),
        zone: zone.tables,
        slot,
        task,
        cpu: &mut *zone.cpu,
        user: zone.user,
        counters,
    }
}

impl<F, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame>
    El1PendingFamilies<'_, F, C, U, G>
{
    fn ipc_transfer(&mut self) -> FamilyCompletion {
        let Some(venue) = &self.ipc else {
            return FamilyCompletion::Forward;
        };
        let Some(frame) = self.frame.arm_frame() else {
            self.frame.record_isa_unsupported_forward();
            return FamilyCompletion::Forward;
        };
        let counters = self.counters;
        let zone = &mut self.zone;
        let current_tasks = self.current_tasks;
        let slot = frame.slot as usize;
        let cur_task = current_tasks.get(slot);
        if let (Some(zone), Some(task), Some(zslot)) =
            (zone.as_mut(), cur_task, SlotId::from_index(slot))
        {
            let orig_x0 = frame.x[0];
            let mut sched = native_scheduler(zone, task, counters, zslot, &mut self.handoff);
            let mut user = file::ValidatedCopy {
                task,
                validator: &file::HardwareValidator,
            };
            let disposition = ipc::serve_ipc(&mut sched, frame, venue, &mut user);
            return carrick_personality_linux::dispatch::transfer_effect(
                &task.linux,
                orig_x0,
                frame.x[0] as i64,
                disposition,
            );
        }

        FamilyCompletion::Forward
    }
    fn task(&self) -> Option<&CurrentTask> {
        self.current_tasks.get(self.frame.task_index())
    }
}

impl<F: Fn(u32) -> *mut u8, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame>
    PendingFileVenue for El1PendingFamilies<'_, F, C, U, G>
{
    fn ordinal(&self) -> u64 {
        self.frame.canonical_ordinal().raw()
    }
    fn inotify_add(&mut self) -> Option<i64> {
        let fd = self.frame.argument(0)? as i32;
        let wd = self.frame.argument(1)?;
        let mask = self.frame.argument(2)? as u32;
        self.task().and_then(|task| {
            inotify::el1_inotify_add_watch(
                self.file_access(),
                fd,
                wd,
                mask,
                task,
                self.fd_map,
                self.object_table,
                self.inotify_table,
                self.name_cache,
                &file::HardwareValidator,
            )
            .ok()
        })
    }
    fn inotify_remove(&mut self) -> Option<i64> {
        let fd = self.frame.argument(0)? as i32;
        let wd = self.frame.argument(1)? as i32;
        self.task().and_then(|task| {
            inotify::el1_inotify_rm_watch(
                self.file_access(),
                fd,
                wd,
                task,
                self.fd_map,
                self.object_table,
                self.inotify_table,
            )
            .ok()
        })
    }
    fn original_argument0(&self) -> u64 {
        self.frame.argument(0).unwrap_or(0)
    }
    fn task_state(&self) -> Option<&LinuxTaskState> {
        self.task().map(|task| &task.linux)
    }
    fn file_operation(&mut self) -> Option<i64> {
        try_serve_file_syscall(
            self.file_access(),
            self.frame,
            self.frame.canonical_ordinal().raw() as usize,
            self.current_tasks,
            self.fd_map,
            self.object_table,
            self.open_table,
            self.inotify_table,
            &self.cache_lookup,
        )
    }
    fn inotify_read(&mut self) -> Option<i64> {
        let fd = self.frame.argument(0)? as i32;
        let buf = self.frame.argument(1)?;
        let len = self.frame.argument(2)? as usize;
        inotify::el1_inotify_read(
            fd,
            buf,
            len,
            self.task()?,
            self.fd_map,
            self.inotify_table,
            &file::HardwareValidator,
        )
        .ok()
    }
    fn wake_is_owed(&self) -> bool {
        self.inotify_table
            .iter()
            .any(DelegatedInotify::wake_is_owed)
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame
            .set_result(carrick_guest_arch::NativeReturnWord(result.raw() as u64));
    }
}
impl<F, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame>
    El1PendingFamilies<'_, F, C, U, G>
{
    fn file_access(&self) -> crate::substrate::file_notification::FileAccess<'_> {
        match (self.zone.as_ref(), self.frame.slot()) {
            (Some(zone), Some(slot)) => {
                crate::substrate::file_notification::FileAccess::notified(zone.tables, slot)
            }
            _ => {
                #[cfg(any(test, feature = "host-test"))]
                {
                    crate::substrate::file_notification::FileAccess::SourceFreeModel
                }
                #[cfg(not(any(test, feature = "host-test")))]
                {
                    crate::substrate::file_notification::FileAccess::Unavailable
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn try_serve_file_syscall<'a, F, G: SyscallFrame>(
    access: crate::substrate::file_notification::FileAccess<'a>,
    frame: &G,
    nr: usize,
    current_tasks: &[CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &'a [DelegatedFile],
    open_table: &[DelegatedOpenFile],
    inotify_table: &[DelegatedInotify],
    cache_lookup: &F,
) -> Option<i64>
where
    F: Fn(u32) -> *mut u8,
{
    let slot = frame.task_index();
    let cur_task = current_tasks.get(slot)?;
    let file_table = cur_task.linux.file_table.load(Ordering::Acquire);
    if file_table == 0 {
        return None;
    }
    let fd = frame.argument(0)? as i32;
    // fd -> open file (this description's offset and flags) -> inode (bytes).
    let (handle, slot_idx) = fd_map_lookup(fd_map, file_table, fd)?;
    if handle == 0 || handle as usize > MAX_ZONE_OPEN_FILES {
        return None;
    }
    let open = open_table.get((handle - 1) as usize)?;
    let inode_handle = open.inode_handle.load(Ordering::Acquire);
    if inode_handle == 0 || inode_handle as usize > MAX_DELEGATED_FILES {
        return None;
    }
    let file = object_table.get((inode_handle - 1) as usize)?;
    if file.state.load(Ordering::Acquire) != DELEGATED_STATE_GUEST {
        return None;
    }
    let file_guard = access.lock(file, inode_handle)?;
    // Re-validate the fd-map slot, the open file and its inode under the
    // inode's lock (which also guards the open-file record).
    let map_slot = fd_map.get(slot_idx)?;
    let slot_incarnation = map_slot.incarnation.load(Ordering::Acquire);
    if slot_incarnation == 0
        || map_slot.handle.load(Ordering::Relaxed) != handle
        || map_slot.fd.load(Ordering::Relaxed) != fd as u32
        || map_slot.file_table.load(Ordering::Relaxed) != file_table
        || slot_incarnation != open.generation.load(Ordering::Acquire)
        || open.inode_handle.load(Ordering::Acquire) != inode_handle
        || !open.is_bound_to(file)
    {
        drop(file_guard);
        return None;
    }

    let cache_ptr = cache_lookup(inode_handle);
    let mut user = file::ValidatedCopy {
        task: cur_task,
        validator: &file::HardwareValidator,
    };
    let args = [frame.argument(1)?, frame.argument(2)?, frame.argument(3)?];
    let zone_file = file::ZoneFile { inode: file, open };
    // SAFETY: the inode is locked and revalidated; `cache_ptr` is its slot.
    let outcome = unsafe {
        serve_locked_file_op(
            &zone_file,
            inotify_table,
            nr,
            args,
            cache_ptr,
            &mut user,
            &TryInstanceLock,
        )
    };
    drop(file_guard);
    outcome.ok()
}

/// How the caller acquires the inotify instances that mark a file it is
/// writing. EL1 never waits (a busy instance forwards the syscall); the host
/// waits, because it has nowhere else to send the operation.
pub trait InstanceLockPolicy {
    fn acquire(&self, instance: &DelegatedInotify) -> bool;
}

/// EL1: take the instance lock only if it is free.
pub struct TryInstanceLock;

impl InstanceLockPolicy for TryInstanceLock {
    fn acquire(&self, instance: &DelegatedInotify) -> bool {
        instance.lock_guest_bounded(EL1_GUEST_LOCK_SPINS)
    }
}

/// Serve one read, write, lseek, pread64 or pwrite64 on a delegated file whose
/// object lock the caller holds, running the single implementation shared by
/// EL1 and the host: lock the marking inotify instances for a write, run the
/// operation, count it, queue IN_MODIFY for each marking watch, release the
/// instances. `args` are the syscall's x1..x3. `Err(Action::Forward)` means
/// this caller cannot serve it exactly (EL1 forwards; the host recalls).
///
/// # Safety
///
/// The caller holds `file`'s lock, has revalidated it as live, and
/// `cache_ptr` is its cache slot.
pub unsafe fn serve_locked_file_op(
    zone_file: &file::ZoneFile<'_>,
    inotify_table: &[DelegatedInotify],
    nr: usize,
    args: [u64; 3],
    cache_ptr: *mut u8,
    user: &mut impl file::UserCopy,
    locks: &impl InstanceLockPolicy,
) -> Result<i64, Action> {
    let file = zone_file.inode;
    // The data event this operation produces on a marking watch: IN_MODIFY
    // for a write, IN_ACCESS for a read (inotify(7)), each only when bytes
    // moved.
    let event: u32 = match nr {
        64 | 68 => 0x02, // LINUX_IN_MODIFY
        63 | 67 => 0x01, // LINUX_IN_ACCESS
        _ => 0,
    };
    let mut locked = [0u32; MAX_DELEGATED_MARKS_PER_FILE];
    let mut num_locked = 0;
    let mut lock_failed = false;
    if event != 0 && file.has_marks() {
        file.for_each_mark(|m| {
            if lock_failed
                || (m.mask & event) == 0
                || m.inotify_handle == 0
                || locked[..num_locked].contains(&m.inotify_handle)
            {
                return;
            }
            match inotify_table.get((m.inotify_handle - 1) as usize) {
                Some(ino)
                    if ino.state.load(Ordering::Acquire) == DELEGATED_STATE_GUEST
                        && ino.spilled.load(Ordering::Acquire) == 0
                        && locks.acquire(ino) =>
                {
                    locked[num_locked] = m.inotify_handle;
                    num_locked += 1;
                }
                _ => lock_failed = true,
            }
        });
    }
    let release = |locked: &[u32]| {
        for &h in locked {
            if let Some(ino) = inotify_table.get((h - 1) as usize) {
                ino.unlock();
            }
        }
    };
    if lock_failed {
        release(&locked[..num_locked]);
        return Err(Action::Forward);
    }
    // SAFETY: forwarded from the caller's contract.
    let outcome = unsafe {
        match nr {
            62 => file::el1_lseek(zone_file, args[0] as i64, args[1] as u32),
            63 => file::read_with(zone_file, cache_ptr, args[0], args[1] as usize, user),
            64 => file::write_with(zone_file, cache_ptr, args[0], args[1] as usize, user),
            67 => file::pread64_with(
                zone_file,
                cache_ptr,
                args[0],
                args[1] as usize,
                args[2] as i64,
                user,
            ),
            68 => file::pwrite64_with(
                zone_file,
                cache_ptr,
                args[0],
                args[1] as usize,
                args[2] as i64,
                user,
            ),
            _ => Err(Action::Forward),
        }
    };
    if event != 0
        && let Ok(moved) = outcome
        && moved > 0
    {
        file.for_each_mark(|m| {
            if (m.mask & event) != 0
                && m.inotify_handle != 0
                && let Some(ino) = inotify_table.get((m.inotify_handle - 1) as usize)
            {
                ino.push_record(m.wd, event, 0, None);
            }
        });
    }
    release(&locked[..num_locked]);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn absent_file_venue_forwards_without_answering_from_empty_tables() {
        let mut frame = TrapFrame::default();
        frame.x[0] = 7;
        frame.x[8] = 62; // lseek
        let tasks = [CurrentTask::new()];
        let counters = Counters::default();
        let action = dispatch_syscall_with_lifecycle(
            &mut frame,
            &counters,
            &tasks,
            &[],
            &[],
            &[],
            &[],
            &InotifyNameCache::new(),
            None::<Zone<'_, sched::FakeCpu, sched::HardwareUserWord>>,
            None,
            None,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(action, Action::Forward);
        assert_eq!(frame.x[0], 7);
        assert_eq!(counters.forwarded[62].load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[62].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn invalid_lifecycle_entry_does_not_publish_result_or_original_argument() {
        use super::super::thread_setup::{LifecycleThread, LifecycleVenue};
        use carrick_el1_abi::{LifecycleHatches, ThreadControlSlot, ThreadLifecyclePage};
        struct Venue {
            page: ThreadLifecyclePage,
            control: ThreadControlSlot,
        }
        impl LifecycleVenue for Venue {
            fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
                task.execution.generation.store(12, Ordering::Release);
                Some(LifecycleThread {
                    page: &self.page,
                    slot: &self.control,
                })
            }
            fn born_slot(
                &self,
                _: &ThreadLifecyclePage,
                _: carrick_el1_abi::EntryRef,
            ) -> Option<&ThreadControlSlot> {
                None
            }
        }
        for scale in [1, 2, 8] {
            for _ in 0..scale {
                let venue = Venue {
                    page: ThreadLifecyclePage::with_hatches(LifecycleHatches::ON),
                    control: ThreadControlSlot::new(),
                };
                assert!(venue.control.publish_visible_tid(41));
                let tasks = [CurrentTask::new()];
                tasks[0].set(carrick_el1_abi::El1TaskId::from_linux_tid(41), 11, 5);
                tasks[0].linux.orig_arg0.store(77, Ordering::Relaxed);
                let counters = Counters::default();
                let mut frame = TrapFrame::default();
                frame.x[0] = 0xfeed;
                frame.x[8] = 178;
                let mut pending = El1PendingFamilies {
                    handoff: None,
                    #[cfg(test)]
                    lifecycle_user: None,
                    frame: &mut frame,
                    counters: &counters,
                    current_tasks: &tasks,
                    fd_map: &[],
                    object_table: &[],
                    open_table: &[],
                    inotify_table: &[],
                    name_cache: &InotifyNameCache::new(),
                    zone: None::<Zone<'_, sched::FakeCpu, sched::HardwareUserWord>>,
                    ipc: None,
                    lifecycle: Some(&venue),
                    cache_lookup: |_| core::ptr::null_mut(),
                };
                assert_eq!(
                    carrick_personality_linux::dispatch::dispatch(178, u64::MAX, &mut pending),
                    carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
                );
                assert_eq!(frame.x[0], 0xfeed);
                assert_eq!(tasks[0].linux.orig_arg0.load(Ordering::Relaxed), 77);
                assert_eq!(counters.served[178].load(Ordering::Relaxed), 0);
                assert_eq!(tasks[0].linux.served_with_work.load(Ordering::Acquire), 0);
            }
        }
    }

    #[test]
    fn stale_futex_handoffs_refuse_the_initiating_entry() {
        use carrick_el1_abi::{Claim, ThreadIdentity};
        use carrick_personality_linux::dispatch::CompletionRoute;
        use carrick_sched_core::{BoundedSpin, ExecutionSlot};
        struct StaleUser<'a> {
            zone: &'a ZoneTables,
            record: carrick_sched_core::RecordId,
            identity: ThreadIdentity,
            mutation: u8,
        }
        impl sched::UserWord for StaleUser<'_> {
            fn read_u32(&self, task: &CurrentTask, _: u64) -> Option<u32> {
                let slot = SlotId::new(0);
                match self.mutation {
                    0 => task.execution.generation.store(12, Ordering::Release),
                    1 => {
                        let mm = self.identity.mm;
                        let address = (0x2000..0x2400)
                            .step_by(4)
                            .find(|address| {
                                ZoneTables::bucket_of(mm, *address)
                                    != ZoneTables::bucket_of(mm, 0x1000)
                            })
                            .unwrap();
                        let guard = self
                            .zone
                            .lock(ZoneTables::bucket_of(mm, address), &BoundedSpin(1024))
                            .unwrap();
                        let sequence = self.zone.next_seq(self.record);
                        self.zone
                            .enqueue(&guard, self.record, sequence, mm, address, u32::MAX, 0)
                            .unwrap();
                        assert!(
                            self.zone
                                .publish_guest_park(&guard, slot, self.record, sequence)
                        );
                        self.zone.clear_current(slot);
                        let mut effects = carrick_sched_core::WakeEffects::default();
                        assert_eq!(
                            self.zone
                                .wake_placed(
                                    &guard,
                                    mm,
                                    address,
                                    u32::MAX,
                                    1,
                                    carrick_sched_core::Waker::El1 { slot },
                                    &mut [],
                                    &mut effects
                                )
                                .unwrap(),
                            1
                        );
                        drop(guard);
                        assert!(self.zone.switch_in(slot).is_some());
                    }
                    _ => {
                        self.zone.clear_current(slot);
                        self.zone.free_record(self.record);
                        let replacement = self.zone.alloc_record(self.identity).unwrap();
                        self.zone.requeue_preempted(slot, replacement);
                        assert!(self.zone.switch_in(slot).is_some());
                    }
                }
                // Bound native idle; no fake family outcome or continuation.
                task.linux.mark_pending_host_work();
                Some(0)
            }
            fn read_u64(&self, _: &CurrentTask, _: u64) -> Option<u64> {
                None
            }
        }
        for scale in [1, 2, 8] {
            for mutation in 0..3 {
                for switched in [false, true] {
                    for _ in 0..scale {
                        let layout = std::alloc::Layout::new::<ZoneTables>();
                        // SAFETY: ZoneTables permits zero initialization, using
                        // its exact alignment/size; Box owns the allocation.
                        let zone = unsafe {
                            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
                            assert!(!ptr.is_null());
                            std::boxed::Box::from_raw(ptr)
                        };
                        let slot = SlotId::new(0);
                        zone.drive(slot, 3);
                        zone.publish_slot(slot, 7, None, 0);
                        let here = ExecutionSlot::zone(slot);
                        zone.occupancy.vacate_any(here);
                        assert!(zone.occupancy.replace(here, 0, 7));
                        zone.enter_guest(slot);
                        let space = zone.spaces.publish_closed(7, 0x7000, 0x7000).unwrap();
                        zone.spaces.open(space);
                        assert!(zone.install_space(slot, 7).is_some());
                        let identity = ThreadIdentity {
                            tid: 41,
                            serial: 1041,
                            mm: 7,
                            file_table: 5,
                            generation: if mutation == 0 { 11 } else { 0 },
                            affinity: 0,
                            lifecycle_page: 0x1000,
                            control_slot: 0x2000,
                        };
                        let record = zone.alloc_record(identity).unwrap();
                        zone.requeue_preempted(slot, record);
                        assert_eq!(zone.switch_in(slot), Some(record));
                        assert!(matches!(zone.record(record).claim(), Claim::OnCpu { .. }));
                        if switched {
                            let successor = zone
                                .alloc_record(ThreadIdentity {
                                    tid: 42,
                                    serial: 1042,
                                    generation: 12,
                                    ..identity
                                })
                                .unwrap();
                            zone.requeue_preempted(slot, successor);
                        }
                        let tasks = [CurrentTask::new()];
                        tasks[0].set(
                            carrick_el1_abi::El1TaskId::from_linux_tid(41),
                            identity.generation,
                            5,
                        );
                        tasks[0].mm.key.store(7, Ordering::Release);
                        tasks[0].mm.thread_generation.store(1041, Ordering::Release);
                        let counters = Counters::default();
                        let mut cpu = sched::FakeCpu::default();
                        let user = StaleUser {
                            zone: &zone,
                            record,
                            identity,
                            mutation,
                        };
                        let mut frame = TrapFrame::default();
                        frame.x[..6].copy_from_slice(&[0x1000, 128, 0, 0, 0, 0]);
                        frame.x[8] = 98;
                        frame.elr = 0x4000;
                        let mut pending = El1PendingFamilies {
                            handoff: None,
                            #[cfg(test)]
                            lifecycle_user: None,
                            frame: &mut frame,
                            counters: &counters,
                            current_tasks: &tasks,
                            fd_map: &[],
                            object_table: &[],
                            open_table: &[],
                            inotify_table: &[],
                            name_cache: &InotifyNameCache::new(),
                            zone: Some(Zone {
                                tables: &zone,
                                cpu: &mut cpu,
                                user: &user,
                            }),
                            ipc: None,
                            lifecycle: None,
                            cache_lookup: |_| core::ptr::null_mut(),
                        };
                        assert_eq!(
                            carrick_personality_linux::dispatch::dispatch(
                                98,
                                u64::MAX,
                                &mut pending
                            ),
                            CompletionRoute::InvalidCompletion,
                            "mutation={mutation} switched={switched}"
                        );
                        assert_eq!(counters.served[98].load(Ordering::Relaxed), 0);
                        assert_eq!(tasks[0].linux.served_with_work.load(Ordering::Acquire), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn allocator_control_requires_test_feature() {
        let mut frame = TrapFrame::default();
        frame.x[8] = carrick_el1_abi::SYS_CARRICK_EL1_CONTROL;
        let counters = Counters::default();
        let action = dispatch_syscall_with_regions(
            &mut frame,
            &counters,
            &[],
            &[],
            &[],
            &[],
            &[],
            &InotifyNameCache::new(),
            None::<Zone<'_, sched::FakeCpu, sched::HardwareUserWord>>,
            |_| core::ptr::null_mut(),
        );
        assert_eq!(
            action,
            if cfg!(feature = "allocator-test-control") {
                Action::Served
            } else {
                Action::Forward
            }
        );
    }

    #[test]
    fn test_dispatch_forwards_all_and_counts() {
        let mut frame = TrapFrame::default();
        let counters = Counters::default();

        frame.x[8] = 64; // write
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[64].load(Ordering::Relaxed), 0);

        frame.x[8] = 172; // getpid
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 1);
        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 1);

        // Out-of-bounds syscall nr
        frame.x[8] = 999;
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
    }

    #[test]
    fn test_concurrent_dispatch_increments() {
        extern crate std;
        let counters = Counters::default();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let mut frame = TrapFrame::default();
                    frame.x[8] = 64; // write
                    for _ in 0..1000 {
                        let action = dispatch_syscall(&mut frame, &counters);
                        assert_eq!(action, Action::Forward);
                    }
                });
            }
        });

        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 8000);
    }

    #[test]
    fn test_dispatch_entry_routes_fault_with_high_bits_and_arbitrary_x8() {
        let counters = Counters::default();
        let mut frame = TrapFrame {
            esr: (0xDEAD_BEEF_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x47,
            far: 0x1000_3000,
            x: {
                let mut x = [0u64; 31];
                x[8] = 172; // SYS_getpid
                x
            },
            ..TrapFrame::default()
        };

        let action = dispatch_entry(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Arbitrary x8 is not treated as a syscall
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn instruction_abort_reaches_the_owner_fault_dispatch() {
        let counters = Counters::default();
        let mut frame = TrapFrame {
            esr: (0x20 << 26) | 0x07,
            far: 0x6000_1000,
            ..TrapFrame::default()
        };
        assert_eq!(dispatch_entry(&mut frame, &counters), Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dispatch_entry_routes_irq() {
        let counters = Counters::default();
        let mut frame = TrapFrame {
            esr: 0,
            ..TrapFrame::default()
        };

        let action = dispatch_entry(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_dispatch_entry_routes_syscall() {
        let counters = Counters::default();
        let mut frame = TrapFrame {
            esr: (0xCAFE_0000_u64 << 32) | (0x15 << 26) | (1 << 25), // SVC64
            far: 0,
            x: {
                let mut x = [0u64; 31];
                x[8] = 172; // SYS_getpid
                x
            },
            ..TrapFrame::default()
        };

        let action = dispatch_entry(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
    }
}
