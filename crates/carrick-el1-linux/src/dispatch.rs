//! Linux syscall dispatch and completion mapping.
extern crate alloc;

use super::cow_resolver::dispatch_fault;
use super::{file, inotify, ipc, lifecycle, sched};
use crate::file::UserCopy;
use crate::sched::LinuxSchedEntry;
use carrick_el1::memory;
use carrick_el1_abi::{
    Action, Counters, CurrentTask, DELEGATED_STATE_GUEST, DelegatedFile, DelegatedInotify,
    DelegatedOpenFile, FdMapSlot, InotifyNameCache, MAX_DELEGATED_FILES, MAX_ZONE_OPEN_FILES,
    SlotId, TrapFrame, ZoneTables, fd_map_lookup,
};
#[cfg(target_os = "none")]
use carrick_el1_abi::{
    EL1_CURRENT_TASKS_BASE, EL1_FD_MAP_BASE, EL1_INOTIFY_TABLE_BASE, EL1_NAME_CACHE_BASE,
    EL1_OBJECT_TABLE_BASE, EL1_OPEN_FILE_TABLE_BASE, EL1_STACK_SLOTS, EL1_ZONE_BASE,
    FD_MAP_CAPACITY, MAX_DELEGATED_INOTIFY,
};
use carrick_personality_linux::abi::entry::{LinuxTaskState, SyscallResult};
use carrick_personality_linux::dispatch::SyscallFrame;
use carrick_personality_linux::dispatch::{EntryCounters, LifecycleWorkCounters};
use carrick_personality_linux::dispatch::{FamilyCompletion, PendingFamilies};
#[cfg(target_os = "none")]
use carrick_personality_linux::pending_anonymous::{DelegatedStep, PermissionStep, RetirementStep};
use carrick_personality_linux::pending_file::PendingFileVenue;
use core::sync::atomic::Ordering;

/// ARM frame access is retained for scheduler/IPC park leaves that have not
/// yet acquired an ISA-neutral saved-context contract.
#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub enum PollTimeoutKind {
    Milliseconds,
    Timespec,
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub enum PollSignalMask {
    Inherit,
    Replace(carrick_signal_core::SignalSet),
}

fn ppoll_timeout_ms(
    seconds: i64,
    nanoseconds: i64,
) -> Result<i32, carrick_syscall_abi::LinuxErrno> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(carrick_syscall_abi::LINUX_EINVAL);
    }
    let milliseconds = seconds
        .saturating_mul(1_000)
        .saturating_add((nanoseconds + 999_999) / 1_000_000);
    Ok(milliseconds.min(i64::from(i32::MAX)) as i32)
}

pub trait GuestDispatchFrame: SyscallFrame {
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal;
    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet;
    /// Whether this execution venue settles owed work at an owned wait's
    /// park boundary and after restoring a signal frame before guest return.
    fn settles_owed_work_at_continuation_boundary(&self) -> bool {
        false
    }
    fn crossing_strict(&self, arm_policy: impl FnOnce() -> bool) -> bool {
        match self.crossing_set() {
            carrick_personality_linux::crossing::HostCrossingSet::X86 => true,
            carrick_personality_linux::crossing::HostCrossingSet::Aarch64 => arm_policy(),
        }
    }
    /// Whether this native call has the poll argument contract.
    fn may_serve_poll(&self) -> bool {
        false
    }
    fn poll_timeout_kind(&self) -> PollTimeoutKind {
        PollTimeoutKind::Timespec
    }
    fn may_serve_descriptor(&self) -> bool {
        false
    }
    fn preflight_host_crossing(&mut self, _ordinal: u64) -> bool {
        true
    }
    fn release_host_object(
        &mut self,
        _binding: carrick_el1_abi::HostObjectBinding,
        _handle: u32,
        _incarnation: u64,
    ) -> bool {
        false
    }
    fn arm_frame(&mut self) -> Option<&mut TrapFrame>;
    fn arm_frame_ref(&self) -> Option<&TrapFrame>;
    fn arm_scheduler(&self) -> bool;
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64>;
    /// Distinguish an ISA-only refusal from a family or venue refusal.
    fn record_isa_unsupported_forward(&self) {}
    fn restore_signal_frame(
        &mut self,
        copy_in: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
    ) -> Result<
        carrick_personality_linux::signal::RestoredSignalFrame,
        carrick_syscall_abi::LinuxErrno,
    > {
        let _ = copy_in;
        Err(carrick_personality_linux::abi::signal::LINUX_ENOSYS)
    }
    fn setup_signal_frame(
        &mut self,
        params: carrick_personality_linux::signal::SignalFrameParams,
        siginfo: Option<&[u8]>,
        copy_out: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
    ) -> Result<carrick_guest_arch::UserVa, carrick_syscall_abi::LinuxErrno> {
        let _ = (params, siginfo, copy_out);
        Err(carrick_personality_linux::abi::signal::LINUX_ENOSYS)
    }
    /// Query exact host-bound descriptions through the carrier. A blocking
    /// adapter suspends inside this call and resumes the same guest poll.
    fn query_host_readiness(
        &mut self,
        _entries: &mut [carrick_el1_abi::HostReadinessEntry],
        _timeout_ms: i32,
        _sig_mask: PollSignalMask,
    ) -> Option<i64> {
        None
    }
}

#[cfg(test)]
mod poll_timeout_tests {
    #[test]
    fn ppoll_timeout_rounds_up_and_rejects_invalid_nanoseconds() {
        assert_eq!(super::ppoll_timeout_ms(0, 1), Ok(1));
        assert_eq!(super::ppoll_timeout_ms(0, 999_999), Ok(1));
        assert_eq!(super::ppoll_timeout_ms(0, 1_000_001), Ok(2));
        assert_eq!(
            super::ppoll_timeout_ms(0, 1_000_000_000),
            Err(carrick_syscall_abi::LINUX_EINVAL)
        );
        assert_eq!(
            super::ppoll_timeout_ms(-1, 0),
            Err(carrick_syscall_abi::LINUX_EINVAL)
        );
        assert_eq!(super::ppoll_timeout_ms(i64::MAX, 999_999_999), Ok(i32::MAX));
    }
}

impl GuestDispatchFrame for TrapFrame {
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        carrick_guest_arch::NativeOrdinal::new(self.x[8])
    }
    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64
    }
    fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
        Some(self)
    }
    fn arm_scheduler(&self) -> bool {
        true
    }
    fn arm_frame_ref(&self) -> Option<&TrapFrame> {
        Some(self)
    }
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    fn restore_signal_frame(
        &mut self,
        copy_in: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
    ) -> Result<
        carrick_personality_linux::signal::RestoredSignalFrame,
        carrick_syscall_abi::LinuxErrno,
    > {
        super::arm_signal::restore_live_arm_signal_frame(self, copy_in)
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
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
#[used]
pub static CARRICK_EL1_ABI_HASH: u64 = carrick_el1_abi::EL1_ABI_LAYOUT_HASH;

/// Dispatch an in-guest Linux syscall at EL1.
pub fn dispatch_syscall(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks: &'static [CurrentTask; EL1_STACK_SLOTS as usize] =
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
        let zone: &'static ZoneTables = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
        #[cfg(target_arch = "aarch64")]
        let slot = SlotId::from_index(frame.slot as usize);
        #[cfg(target_arch = "aarch64")]
        {
            let (nr, flags) = (frame.x[8], frame.x[0]);
            // Without a published lifecycle no owner can retain this thread.
            let unowned = arm_process_call_claimed(nr, flags, || false);
            let (Some(slot), Some(task)) = (slot, current_tasks.get(frame.slot as usize)) else {
                return refuse_owner_process_call(frame, counters, current_tasks);
            };
            let Some((page, control)) = task.lifecycle_refs() else {
                return fallback_or_refuse_arm_process_call(
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
                    unowned,
                );
            };
            let refused = || {
                arm_owner_must_serve(
                    nr,
                    flags,
                    || arm_thread_group_owned(zone, task, page),
                    carrick_el1_abi::Lifecycle::live(page),
                )
            };
            let mut saved = alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
            sched::ThreadCpu::save(&mut sched::HardwareCpu, frame, &mut saved);
            let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
            let mut service =
                match super::aarch64_process::Aarch64NativeProcessService::new(task, slot) {
                    Ok(service) => service,
                    Err(_) => {
                        return fallback_or_refuse_arm_process_call(
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
                            refused(),
                        );
                    }
                };
            let route = dispatch_arm_syscall_with_native_process(
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
                lifecycle::guest_venue(),
                page,
                control,
                &saved.native,
                ttbr0,
                &mut service,
                |handle| carrick_el1_abi::delegated_file_cache_va(handle) as *mut u8,
            );
            match route {
                Ok(route) => resolve_arm_process_route(route, page, frame, counters, current_tasks),
                Err(_) => fallback_or_refuse_arm_process_call(
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
                    refused(),
                ),
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
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
                Some(Zone {
                    tables: zone,
                    cpu: &mut sched::HardwareCpu,
                    user: &sched::HardwareUserWord,
                }),
                ipc::guest_venue(frame.slot as u32).as_ref(),
                |handle| carrick_el1_abi::delegated_file_cache_va(handle) as *mut u8,
            )
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let nr = frame.x[8] as usize;
        // SAFETY: entry retains the registered EL1 region, or no mapping is registered.
        let is_strict =
            unsafe { carrick_el1_abi::host_aperture_control() }.is_none_or(|ctrl| ctrl.is_strict());
        let canonical = carrick_personality_linux::abi::entry::CanonicalOrdinal::new(frame.x[8]);
        let decision = carrick_personality_linux::crossing::evaluate_host_crossing(
            carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
            is_strict,
            Some(canonical),
            Some(carrick_personality_linux::crossing::NativeNr(frame.x[8])),
            Some(&counters.refused),
            |ret| frame.x[0] = ret.raw() as u64,
        );
        match decision {
            carrick_personality_linux::crossing::HostCrossingDecision::Refused => Action::Served,
            carrick_personality_linux::crossing::HostCrossingDecision::Forward => {
                if nr < 512 {
                    counters.forwarded[nr].fetch_add(1, Ordering::Relaxed);
                }
                Action::Forward
            }
        }
    }
}

/// Production ARM admission and the single process capability passed to the
/// shared Linux pipeline. The VM-free witness calls this exact adapter.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_arm_syscall_with_native_process<F, C, U, X>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &'static [CurrentTask],
    fd_map: &[FdMapSlot],
    object_table: &[DelegatedFile],
    open_table: &[DelegatedOpenFile],
    inotify_table: &[DelegatedInotify],
    name_cache: &InotifyNameCache,
    zone: Option<Zone<'_, C, U>>,
    ipc: Option<&ipc::IpcVenue<'_>>,
    lifecycle: Option<&dyn lifecycle::LifecycleVenue>,
    page: &'static carrick_el1_abi::ThreadLifecyclePage,
    control: &'static carrick_el1_abi::ThreadControlSlot,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    service: &mut super::aarch64_process::Aarch64NativeProcessService<'static, X>,
    cache_lookup: F,
) -> Result<
    carrick_personality_linux::dispatch::CompletionRoute,
    super::native_process_runtime::NativeProcessError,
>
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    X: super::aarch64_process::ForkStockCrossing,
{
    let source = carrick_el1_abi::BornInZoneSource {
        zone: service.zone,
        slot: service.slot,
    };
    let task = service.task;
    super::aarch64_process::with_process_entry(
        source,
        service.task,
        native,
        ttbr0,
        page,
        control,
        service,
        |process| {
            let route = dispatch_syscall_with_native(
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
                Some(&mut *process),
                Some(source),
                None,
                cache_lookup,
            );
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            if route == carrick_personality_linux::dispatch::CompletionRoute::Served
                && let Some(delivery) =
                    super::arm_signal::deliver_on_user_return(task, process, frame)
            {
                return delivery;
            }
            #[cfg(test)]
            let _ = task;
            route
        },
    )
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn arm_process_call_claimed(
    nr: u64,
    flags: u64,
    registered: impl FnOnce() -> bool,
) -> bool {
    nr == 435
        || (nr == 220 && flags & 0x0001_0000 == 0)
        || (matches!(nr, 260 | 93 | 94 | 95 | 58 | 139) && registered())
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn arm_process_refusal_must_abort(nr: u64) -> bool {
    matches!(nr, 93 | 94)
}

/// Whether the retained process owner must serve this call, so that neither
/// the host nor the owner-free pipeline may answer it. A non-last thread's raw
/// `exit` is never the owner's: the host retires that thread.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn arm_owner_must_serve(
    nr: u64,
    flags: u64,
    owned: impl FnOnce() -> bool,
    live: u32,
) -> bool {
    !(nr == carrick_personality_linux::lifecycle::SYS_EXIT as u64 && live > 1)
        && arm_process_call_claimed(nr, flags, owned)
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn resolve_arm_process_route(
    route: carrick_personality_linux::dispatch::CompletionRoute,
    page: &carrick_el1_abi::ThreadLifecyclePage,
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
) -> Action {
    match route {
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody => Action::HostCustody,
        carrick_personality_linux::dispatch::CompletionRoute::Served => Action::Served,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork => Action::ServedWithWork,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended => Action::Idle,
        carrick_personality_linux::dispatch::CompletionRoute::Forward => {
            let live = carrick_el1_abi::Lifecycle::live(page);
            if arm_owner_must_serve(frame.x[8], frame.x[0], || true, live) {
                refuse_owner_process_call(frame, counters, current_tasks)
            } else {
                Action::Forward
            }
        }
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion => {
            invalid_completion(NativeInvariant::EntryBinding)
        }
    }
}

/// Whether an admitted owner retains this thread's group at any address.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn arm_thread_group_owned(
    zone: &ZoneTables,
    task: &CurrentTask,
    page: &carrick_el1_abi::ThreadLifecyclePage,
) -> bool {
    task.visible_pid()
        .is_some_and(|pid| super::aarch64_process::registry().owns_thread_group(zone, page, pid))
}

/// A thread the process venue could not admit still runs every call the
/// owner need not serve through the ordinary pipeline (never a blanket
/// ENOSYS); `refused` names a call only the retained owner may answer.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn fallback_or_refuse_arm_process_call<F, C, U>(
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
    refused: bool,
) -> Action
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
{
    if refused {
        refuse_owner_process_call(frame, counters, current_tasks)
    } else {
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
            ipc,
            cache_lookup,
        )
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn refuse_owner_process_call(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
) -> Action {
    let nr = frame.x[8] as usize;
    if arm_process_refusal_must_abort(nr as u64) {
        invalid_completion(NativeInvariant::EntryBinding);
    }
    let task = current_tasks
        .get(frame.slot as usize)
        .unwrap_or_else(|| invalid_completion(NativeInvariant::EntryBinding));
    task.linux.orig_arg0.store(frame.x[0], Ordering::Relaxed);
    frame.x[0] = (-38_i64) as u64;
    if nr < 512 {
        counters.served[nr].fetch_add(1, Ordering::Relaxed);
    }
    task.linux.record_completed_with_work();
    Action::ServedWithWork
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
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    if matches!(frame.esr, 0xfffc..=0xfffe) {
        return arm_signal_user_return(frame);
    }
    let action = if frame.esr == 0 {
        dispatch_irq(frame, counters)
    } else if matches!((frame.esr >> 26) & 0x3f, 0x20 | 0x24) {
        dispatch_fault(frame, counters)
    } else {
        dispatch_syscall(frame, counters)
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    if action == Action::Served
        && (frame.esr == 0 || matches!((frame.esr >> 26) & 0x3f, 0x20 | 0x24))
    {
        return arm_signal_user_return(frame);
    }
    action
}

/// The one native signal checkpoint at the actual EL0 return boundary. The
/// syscall work ledger and scheduler resume result have already settled here;
/// IRQ, fault and SVC returns all pass through the same owner.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
fn arm_signal_user_return(frame: &mut TrapFrame) -> Action {
    let current_tasks: &'static [CurrentTask; EL1_STACK_SLOTS as usize] =
        unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
    let fatal_owner_cancel = frame.esr == 0xfffc;
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        if fatal_owner_cancel {
            invalid_completion(NativeInvariant::EntryBinding)
        }
        return Action::Served;
    };
    let Some((page, control)) = task.lifecycle_refs() else {
        if fatal_owner_cancel {
            invalid_completion(NativeInvariant::EntryBinding)
        }
        return Action::Served;
    };
    if !control.native_signal_owner()
        || (frame.esr != 0xfffc && !carrick_el1_abi::Lifecycle::gate(page).serves_ring())
    {
        if fatal_owner_cancel {
            invalid_completion(NativeInvariant::EntryBinding)
        }
        return Action::Served;
    }
    let Some(slot) = SlotId::from_index(frame.slot as usize) else {
        invalid_completion(NativeInvariant::EntryBinding)
    };
    let zone: &'static ZoneTables = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
    let source = carrick_el1_abi::BornInZoneSource { zone, slot };
    if frame.esr != 0xfffc
        && !(frame.esr == 0xfffe
            && frame.x[0] == carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64)
        && carrick_el1::isa::signal_ingress_guest().is_empty()
        && control.zone_record().is_some_and(|record| {
            !super::aarch64_process::registry().signal_checkpoint_needed(zone, record)
        })
    {
        return Action::Served;
    }
    let mut saved = alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    sched::ThreadCpu::save(&mut sched::HardwareCpu, frame, &mut saved);
    let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
    let mut service = super::aarch64_process::Aarch64NativeProcessService::new(task, slot)
        .unwrap_or_else(|_| invalid_completion(NativeInvariant::EntryBinding));
    let delivered = super::aarch64_process::with_process_entry(
        source,
        task,
        &saved.native,
        ttbr0,
        page,
        control,
        &mut service,
        |process| super::arm_signal::deliver_on_user_return(task, process, frame),
    )
    .unwrap_or_else(|_| invalid_completion(NativeInvariant::EntryBinding));
    match delivered {
        None | Some(carrick_personality_linux::dispatch::CompletionRoute::Served) => Action::Served,
        Some(carrick_personality_linux::dispatch::CompletionRoute::Suspended) => Action::Idle,
        Some(_) => invalid_completion(NativeInvariant::EntryBinding),
    }
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
        None,
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
    process: Option<&'a mut dyn lifecycle::ProcessNative<LegacyDispatchContext>>,
    cache_lookup: F,
) -> Action
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
{
    match dispatch_syscall_with_native(
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
        process,
        None,
        None,
        cache_lookup,
    ) {
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody => Action::HostCustody,
        carrick_personality_linux::dispatch::CompletionRoute::Served => Action::Served,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork => Action::ServedWithWork,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended => Action::Idle,
        carrick_personality_linux::dispatch::CompletionRoute::Forward => Action::Forward,
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion => {
            invalid_completion(NativeInvariant::EntryBinding)
        }
    }
}

type LegacyDispatchContext = carrick_el1_abi::Aarch64ParkedContext;

/// Exact context capability for the shared dispatcher. Only the ARM context
/// can obtain an ARM scheduler source or consume an ARM scheduler receipt.
pub trait DispatchContext: carrick_el1_abi::EntryContext {
    fn arm_source(
        zone: &ZoneTables,
        slot: SlotId,
    ) -> Option<carrick_el1_abi::BornInZoneSource<'_, Self>>;
    fn arm_receipt(
        receipt: carrick_el1_abi::EntryHandoffReceipt<carrick_sched_core::Aarch64ParkedContext>,
    ) -> Option<carrick_el1_abi::EntryHandoffReceipt<Self>>;
}
impl DispatchContext for carrick_sched_core::ThreadCtx {
    fn arm_source(
        _: &ZoneTables,
        _: SlotId,
    ) -> Option<carrick_el1_abi::BornInZoneSource<'_, Self>> {
        None
    }
    fn arm_receipt(
        receipt: carrick_el1_abi::EntryHandoffReceipt<carrick_sched_core::Aarch64ParkedContext>,
    ) -> Option<carrick_el1_abi::EntryHandoffReceipt<Self>> {
        let _ = receipt;
        None
    }
}
impl DispatchContext for carrick_sched_core::ParkedContextWords {
    fn arm_source(
        _: &ZoneTables,
        _: SlotId,
    ) -> Option<carrick_el1_abi::BornInZoneSource<'_, Self>> {
        None
    }
    fn arm_receipt(
        _: carrick_el1_abi::EntryHandoffReceipt<carrick_sched_core::Aarch64ParkedContext>,
    ) -> Option<carrick_el1_abi::EntryHandoffReceipt<Self>> {
        None
    }
}
impl DispatchContext for carrick_sched_core::Aarch64ParkedContext {
    fn arm_source(
        zone: &ZoneTables,
        slot: SlotId,
    ) -> Option<carrick_el1_abi::BornInZoneSource<'_, Self>> {
        Some(carrick_el1_abi::BornInZoneSource { zone, slot })
    }
    fn arm_receipt(
        receipt: carrick_el1_abi::EntryHandoffReceipt<carrick_sched_core::Aarch64ParkedContext>,
    ) -> Option<carrick_el1_abi::EntryHandoffReceipt<Self>> {
        Some(receipt)
    }
}

/// Supply native process and anonymous custody to the same full Linux pipeline.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_syscall_with_native<'a, F, C, U, G, Context>(
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
    process: Option<&'a mut dyn lifecycle::ProcessNative<Context>>,
    source: Option<carrick_el1_abi::BornInZoneSource<'a, Context>>,
    anonymous: Option<
        &'a mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue,
    >,
    cache_lookup: F,
) -> carrick_personality_linux::dispatch::CompletionRoute
where
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext + 'a,
{
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
        process,
        source,
        anonymous,
        cache_lookup,
    };
    let control = if cfg!(feature = "allocator-test-control") {
        carrick_el1_abi::SYS_CARRICK_EL1_CONTROL
    } else {
        u64::MAX
    };
    let route = carrick_personality_linux::dispatch::dispatch(ordinal, control, &mut pending);
    if pending.frame.arm_frame_ref().is_some()
        && let Some(process) = pending.process.as_deref_mut()
        && let Some(reason) = process.take_run_failure()
    {
        super::native_run_failure::complete_native_run_failure(process.binding(), reason);
    }
    route
}

/// Native preparation, scheduling and completion retain an exact execution
/// binding. Missing frames and failed completion authentication share this
/// fail-stop transport; a completed effect must never be replayed by forwarding.
pub enum NativeInvariant {
    EntryBinding,
    PhysicalCustody(&'static str),
    MissingNativeFrame,
    RevisionCredit,
    SignalNumber,
    ProcessGraph(super::process_owner::GuestProcessInvariant),
}

impl core::fmt::Debug for NativeInvariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EntryBinding => f.write_str("EntryBinding"),
            Self::PhysicalCustody(reason) => {
                f.debug_tuple("PhysicalCustody").field(reason).finish()
            }
            Self::MissingNativeFrame => f.write_str("MissingNativeFrame"),
            Self::RevisionCredit => f.write_str("RevisionCredit"),
            Self::SignalNumber => f.write_str("SignalNumber"),
            Self::ProcessGraph(invariant) => {
                f.debug_tuple("ProcessGraph").field(invariant).finish()
            }
        }
    }
}

pub fn invalid_completion(reason: NativeInvariant) -> ! {
    #[cfg(target_os = "none")]
    {
        let _ = reason;
        carrick_el1::substrate::sched::hw::fatal_entry_binding();
    }
    #[cfg(not(target_os = "none"))]
    carrick_fatal::carrick_fatal!(
        "el1::entry_completion",
        "native entry invariant: {reason:?}"
    )
}

pub struct El1PendingFamilies<
    'a,
    F,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame = TrapFrame,
    Context: DispatchContext = carrick_sched_core::ThreadCtx,
> {
    pub(super) handoff:
        Option<carrick_el1_abi::EntryHandoffReceipt<carrick_sched_core::Aarch64ParkedContext>>,
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
    pub(super) process: Option<&'a mut dyn lifecycle::ProcessNative<Context>>,
    pub(super) source: Option<carrick_el1_abi::BornInZoneSource<'a, Context>>,
    pub(super) anonymous:
        Option<&'a mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue>,
    pub(super) cache_lookup: F,
}
impl<
    'a,
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext,
> PendingFamilies<'a, Context> for El1PendingFamilies<'a, F, C, U, G, Context>
{
    fn resume_owned_continuation(&mut self) -> Option<lifecycle::LifecycleOutcome> {
        self.process.as_deref_mut()?.resume_owned_continuation()
    }
    fn may_serve_poll(&self) -> bool {
        self.frame.may_serve_poll()
    }
    fn may_serve_descriptor(&self) -> bool {
        if self.frame.may_serve_descriptor() {
            return true;
        }
        let ordinal = self.frame.canonical_ordinal().raw();
        if ![
            carrick_personality_linux::crossing::nr::DUP,
            carrick_personality_linux::crossing::nr::DUP3,
            carrick_personality_linux::crossing::nr::CLOSE,
        ]
        .iter()
        .any(|nr| nr.raw() == ordinal)
        {
            return false;
        }
        // Native fork owns its copied file slots; the host has no child table.
        // Host views and inotify retain their existing mutation owner.
        self.task().is_some_and(|task| {
            let table = task.linux.file_table.load(Ordering::Acquire);
            let fd = self.frame.argument(0).unwrap_or(0) as i32;
            fd_map_lookup(self.fd_map, table, fd).is_some_and(|(handle, index)| {
                handle & carrick_el1_abi::FD_HANDLE_INOTIFY_TAG == 0
                    && self.fd_map[index].fd_flags.load(Ordering::Acquire) & FdMapSlot::HOST_VIEW
                        == 0
            })
        })
    }
    fn take_handoff_receipt(&mut self) -> Option<carrick_el1_abi::EntryHandoffReceipt<Context>> {
        self.process
            .as_deref_mut()
            .and_then(|process| process.take_handoff_receipt())
            .or_else(|| self.handoff.take().and_then(Context::arm_receipt))
    }
    fn binding(&self) -> Option<carrick_el1_abi::ExecutionBinding> {
        self.task().map(super::common_entry::execution_binding)
    }
    fn record_source(&self) -> Option<carrick_el1_abi::BornInZoneSource<'a, Context>> {
        self.source
            .or_else(|| Context::arm_source(self.zone.as_ref()?.tables, self.frame.slot()?))
    }
    fn anonymous_venue(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue> {
        if self.anonymous.is_some() {
            return self.anonymous.as_mut().map(|anonymous| &mut **anonymous as &mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue);
        }
        #[cfg(target_os = "none")]
        {
            Some(self)
        }
        #[cfg(not(target_os = "none"))]
        {
            None
        }
    }
    fn file_venue(&mut self) -> Option<&mut dyn PendingFileVenue> {
        Some(self)
    }
    fn sched_venue(&mut self) -> Option<&mut dyn carrick_personality_linux::sched::SchedVenue> {
        Some(self)
    }
    fn signal_native(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::signal::SignalNative<'a>> {
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
    fn poll(&mut self) -> FamilyCompletion {
        let Some(task) = self.task() else {
            return FamilyCompletion::Forward;
        };
        let fds_ptr = self.frame.argument(0).unwrap_or(0);
        let nfds = self.frame.argument(1).unwrap_or(0) as usize;
        let timeout_kind = self.frame.poll_timeout_kind();
        let timeout_ms = if matches!(timeout_kind, PollTimeoutKind::Milliseconds) {
            self.frame.argument(2).unwrap_or(0) as i32
        } else {
            let tmo_ptr = self.frame.argument(2).unwrap_or(0);
            if tmo_ptr == 0 {
                -1
            } else {
                let mut ts = [0u8; 16];
                let mut user = file::ValidatedCopy {
                    task,
                    validator: &file::HardwareValidator,
                };
                if !user.copy_in(&mut ts, tmo_ptr) {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                    );
                }
                let mut seconds = [0u8; 8];
                let mut nanoseconds = [0u8; 8];
                seconds.copy_from_slice(&ts[..8]);
                nanoseconds.copy_from_slice(&ts[8..]);
                match ppoll_timeout_ms(i64::from_le_bytes(seconds), i64::from_le_bytes(nanoseconds))
                {
                    Ok(milliseconds) => milliseconds,
                    Err(errno) => return FamilyCompletion::Complete(errno.guest_retval()),
                }
            }
        };
        let sig_mask = if matches!(timeout_kind, PollTimeoutKind::Milliseconds) {
            PollSignalMask::Inherit
        } else {
            let mask_ptr = self.frame.argument(3).unwrap_or(0);
            if mask_ptr == 0 {
                PollSignalMask::Inherit
            } else {
                let mut bits = [0u8; 8];
                if self.frame.argument(4).unwrap_or(0) != bits.len() as u64 {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                    );
                }
                let mut user = file::ValidatedCopy {
                    task,
                    validator: &file::HardwareValidator,
                };
                if !user.copy_in(&mut bits, mask_ptr) {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                    );
                }
                PollSignalMask::Replace(
                    carrick_signal_core::SignalSet::from_bits(u64::from_le_bytes(bits))
                        .without(carrick_signal_core::policy::Signal::KILL)
                        .without(carrick_signal_core::policy::Signal::STOP),
                )
            }
        };
        if nfds == 0 {
            let mut empty = [];
            return FamilyCompletion::Complete(
                self.frame
                    .query_host_readiness(&mut empty, timeout_ms, sig_mask)
                    .unwrap_or(0),
            );
        }
        if nfds > 1024 {
            return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        }
        let mut pollfds = alloc::vec![super::file_table::PollFd::default(); nfds];
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                pollfds.as_mut_ptr() as *mut u8,
                nfds * core::mem::size_of::<super::file_table::PollFd>(),
            )
        };
        let copied = {
            let mut user = file::ValidatedCopy {
                task,
                validator: &file::HardwareValidator,
            };
            user.copy_in(bytes, fds_ptr)
        };
        if !copied {
            return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EFAULT.guest_retval());
        }
        let file_table = task
            .linux
            .file_table
            .load(core::sync::atomic::Ordering::Acquire)
            .max(1);
        let host_entries = super::file_table::host_readiness_entries(
            self.fd_map,
            self.open_table,
            file_table,
            &pollfds,
        );
        if let Some(mut entries) = host_entries {
            let already_ready = super::file_table::resolve_poll_with_host_readiness(
                self.fd_map,
                self.open_table,
                self.object_table,
                self.ipc,
                file_table,
                &mut pollfds,
                Some(&entries),
            );
            let host_timeout = if already_ready > 0 { 0 } else { timeout_ms };
            if let Some(result) =
                self.frame
                    .query_host_readiness(&mut entries, host_timeout, sig_mask)
            {
                if result < 0 {
                    return FamilyCompletion::Complete(result);
                }
                let ready = super::file_table::resolve_poll_with_host_readiness(
                    self.fd_map,
                    self.open_table,
                    self.object_table,
                    self.ipc,
                    file_table,
                    &mut pollfds,
                    Some(&entries),
                );
                let out_bytes = unsafe {
                    core::slice::from_raw_parts(
                        pollfds.as_ptr() as *const u8,
                        nfds * core::mem::size_of::<super::file_table::PollFd>(),
                    )
                };
                let Some(task) = self.task() else {
                    return FamilyCompletion::Forward;
                };
                let mut user = file::ValidatedCopy {
                    task,
                    validator: &file::HardwareValidator,
                };
                if !user.copy_out(fds_ptr, out_bytes) {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                    );
                }
                return FamilyCompletion::Complete(ready as i64);
            }
        }
        let Some(task) = self.task() else {
            return FamilyCompletion::Forward;
        };
        let mut user = file::ValidatedCopy {
            task,
            validator: &file::HardwareValidator,
        };
        let ready = super::file_table::resolve_poll(
            self.fd_map,
            self.open_table,
            self.object_table,
            self.ipc,
            file_table,
            &mut pollfds,
        );
        let out_bytes = unsafe {
            core::slice::from_raw_parts(
                pollfds.as_ptr() as *const u8,
                nfds * core::mem::size_of::<super::file_table::PollFd>(),
            )
        };
        if !user.copy_out(fds_ptr, out_bytes) {
            return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EFAULT.guest_retval());
        }
        if ready > 0 || timeout_ms == 0 {
            FamilyCompletion::Complete(ready as i64)
        } else {
            let slot = self.frame.slot();
            let mut continuation = super::file_table::PollContinuation::new(
                file_table, pollfds, timeout_ms, fds_ptr, slot,
            );
            if let (Some(zone), Some(_)) = (self.zone.as_ref(), slot) {
                continuation.release_capacity(zone.tables);
            }
            FamilyCompletion::Complete(ready as i64)
        }
    }
    fn descriptor(&mut self) -> FamilyCompletion {
        let Some(task) = self.task() else {
            return FamilyCompletion::Forward;
        };
        let file_table = task.linux.file_table.load(Ordering::Acquire).max(1);
        let ordinal = self.frame.canonical_ordinal().raw();
        let old = self.frame.argument(0).unwrap_or(0) as i32;
        let result = match ordinal {
            nr if nr == carrick_personality_linux::crossing::nr::DUP.raw() => {
                super::file_table::dup_host_binding(
                    self.fd_map,
                    self.open_table,
                    file_table,
                    old,
                    0,
                    super::file_table::GUEST_FD_LIMIT,
                    false,
                )
            }
            nr if nr == carrick_personality_linux::crossing::nr::DUP3.raw() => {
                let new = self.frame.argument(1).unwrap_or(0) as i32;
                let flags = self.frame.argument(2).unwrap_or(0);
                if flags & !carrick_syscall_abi::LINUX_O_CLOEXEC != 0 || old == new {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                    );
                }
                super::file_table::dup2_host_binding(
                    self.fd_map,
                    self.open_table,
                    file_table,
                    old,
                    new,
                    flags != 0,
                )
            }
            nr if nr == carrick_syscall_abi::CARRICK_PRIVATE_X86_DUP2 => {
                let new = self.frame.argument(1).unwrap_or(0) as i32;
                super::file_table::dup2_host_binding(
                    self.fd_map,
                    self.open_table,
                    file_table,
                    old,
                    new,
                    false,
                )
            }
            nr if nr == carrick_personality_linux::crossing::nr::CLOSE.raw() => {
                super::file_table::close_host_binding(self.fd_map, self.open_table, file_table, old)
            }
            _ => return FamilyCompletion::Forward,
        };
        let Some(change) = result else {
            let errno = if ordinal == carrick_personality_linux::crossing::nr::DUP.raw()
                && fd_map_lookup(self.fd_map, file_table, old).is_some()
            {
                carrick_syscall_abi::LINUX_EMFILE
            } else {
                carrick_syscall_abi::LINUX_EBADF
            };
            return FamilyCompletion::Complete(errno.guest_retval());
        };
        if let Some(release) = change.release {
            task.linux.mark_pending_host_work();
            let binding = self
                .open_table
                .get(release.handle.checked_sub(1).unwrap_or(u32::MAX) as usize)
                .and_then(DelegatedOpenFile::host_object);
            if binding.is_some_and(|binding| binding.stdio_fd().is_some())
                && !binding.is_some_and(|binding| {
                    self.frame
                        .release_host_object(binding, release.handle, release.incarnation)
                })
            {
                return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EIO.guest_retval());
            }
        }
        FamilyCompletion::Complete(
            if ordinal == carrick_personality_linux::crossing::nr::CLOSE.raw() {
                0
            } else {
                i64::from(change.fd)
            },
        )
    }
    fn original_argument0(&self) -> u64 {
        self.frame.argument(0).unwrap_or(0)
    }
    fn return_requires_host_boundary(&self) -> bool {
        // ARM native process returns and the newly published getpid projection
        // otherwise bypass the host's owned return-event publisher. Retain the
        // completed result through the same boundary as other owed host work.
        self.frame.arm_frame_ref().is_some()
            && (self.process.is_some()
                || self.frame.canonical_ordinal().raw()
                    == carrick_personality_linux::lifecycle::SYS_GETPID as u64)
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame
            .set_result(carrick_guest_arch::NativeReturnWord(result.raw() as u64));
    }
    fn ring_first_strict(&self) -> bool {
        self.frame.crossing_strict(|| {
            #[cfg(all(target_os = "none", target_arch = "aarch64"))]
            {
                // SAFETY: ARM entry maps the ABI aperture for the lifetime of EL1.
                unsafe { carrick_el1_abi::aperture_control() }.is_strict()
            }
            #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
            {
                // SAFETY: this entry retains its registered region; tests without a
                // region return None before any pointer is dereferenced.
                unsafe { carrick_el1_abi::host_aperture_control() }
                    .is_none_or(|ctrl| ctrl.is_strict())
            }
        })
    }
    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        self.frame.crossing_set()
    }
    fn settles_owed_work_at_continuation_boundary(&self) -> bool {
        self.frame.settles_owed_work_at_continuation_boundary()
    }
    fn native_number(&self) -> Option<carrick_personality_linux::crossing::NativeNr> {
        Some(carrick_personality_linux::crossing::NativeNr(
            self.frame.native_number().raw(),
        ))
    }
    fn preflight_host_crossing(&mut self, ordinal: u64) -> bool {
        self.frame.preflight_host_crossing(ordinal)
    }
    fn refused_counters(&self) -> Option<&'a [core::sync::atomic::AtomicU64]> {
        Some(&self.counters.refused)
    }
    fn lifecycle_native(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::lifecycle::LifecycleNative<'a>> {
        if self.lifecycle.is_none() && self.process.is_none() {
            return None;
        }
        self.current_tasks.get(self.frame.task_index())?;
        Some(self)
    }
    fn identity_native(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::identity::IdentityNative<'a>> {
        self.process.as_ref()?;
        self.current_tasks.get(self.frame.task_index())?;
        Some(self)
    }
    fn sysinfo_native(
        &mut self,
    ) -> Option<&mut dyn carrick_personality_linux::sysinfo::SysinfoNative<'a>> {
        self.process.as_ref()?;
        self.current_tasks.get(self.frame.task_index())?;
        Some(self)
    }
    fn guest_isa(&self) -> carrick_guest_arch::GuestIsa {
        if self.frame.arm_scheduler() {
            carrick_guest_arch::GuestIsa::Aarch64
        } else {
            carrick_guest_arch::GuestIsa::X86_64
        }
    }
    fn ipc_native(&mut self) -> Option<&mut dyn carrick_personality_linux::ipc::IpcNative<'a>> {
        self.process.as_ref()?;
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
            1 => carrick_el1::alloc::run_guest_allocator_test(frame.x[1], frame.x[2]),
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
                    carrick_el1::substrate::sched::object_wait::OperationResumePc::new(
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
        self.lifecycle.is_some() || self.process.is_some()
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
                carrick_el1::substrate::sched::object_wait::space_access(zone.tables, slot),
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
impl<
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext,
> carrick_personality_linux::pending_anonymous::PendingAnonymousVenue
    for El1PendingFamilies<'_, F, C, U, G, Context>
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
        let access = carrick_el1::substrate::sched::object_wait::space_access(zone.tables, slot);
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
        let access = carrick_el1::substrate::sched::object_wait::space_access(zone.tables, slot);
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
        let access = carrick_el1::substrate::sched::object_wait::space_access(zone.tables, slot);
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
    handoff: &'s mut Option<
        carrick_el1_abi::EntryHandoffReceipt<carrick_sched_core::Aarch64ParkedContext>,
    >,
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

impl<F, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame, Context: DispatchContext>
    El1PendingFamilies<'_, F, C, U, G, Context>
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

impl<
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext,
> carrick_personality_linux::sched::SchedVenue for El1PendingFamilies<'_, F, C, U, G, Context>
{
    fn yield_current(&mut self) -> FamilyCompletion {
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return FamilyCompletion::Complete(0);
        };
        let Some(slot) = self.frame.slot() else {
            return FamilyCompletion::Complete(0);
        };
        let Some(zone) = &mut self.zone else {
            return FamilyCompletion::Complete(0);
        };
        let Some(frame) = self.frame.arm_frame() else {
            // x86 ordinal 24 maps to this shared canonical call. It has no
            // ARM frame to rotate, but still completes in ring.
            return FamilyCompletion::Complete(0);
        };
        if task.linux.has_pending_host_work()
            || task.lifecycle_refs().is_some_and(|(page, control)| {
                page.pending().load().0 != 0 || control.pending().load().0 != 0
            })
        {
            return FamilyCompletion::CompleteWithWork(0);
        }
        if zone.tables.runnable_head(slot).is_none() {
            return FamilyCompletion::Complete(0);
        }
        match native_scheduler(zone, task, self.counters, slot, &mut self.handoff)
            .yield_queued(frame)
        {
            Some(carrick_core::Served::Returned { switched: true }) => {
                FamilyCompletion::Switched(0)
            }
            Some(carrick_core::Served::Returned { switched: false }) => {
                FamilyCompletion::Complete(0)
            }
            Some(carrick_core::Served::Idle) => FamilyCompletion::Suspended,
            // A late scheduler guard or failed handoff must retain the
            // completed syscall while the host settles pending work.
            None => FamilyCompletion::CompleteWithWork(0),
        }
    }
    fn argument(&self, index: usize) -> u64 {
        self.frame.argument(index).unwrap_or(0)
    }
    fn current_pid(&self) -> Option<u32> {
        self.current_tasks
            .get(self.frame.task_index())
            .and_then(|t| t.visible_pid())
    }
    fn pid_exists(&self, pid: u32) -> Option<bool> {
        if self.current_pid() == Some(pid) {
            return Some(true);
        }
        let binding = carrick_personality_linux::lifecycle::LifecycleNative::binding(self)?;
        let process = self.process.as_deref()?;
        if process.binding() != binding {
            return None;
        }
        process.pid_exists(pid)
    }
    fn copy_out(&mut self, dst: carrick_guest_arch::UserVa, src: &[u8]) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_out(dst.raw(), src);
        }
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        crate::file::UserCopy::copy_out(
            &mut crate::file::ValidatedCopy {
                task,
                validator: &crate::file::HardwareValidator,
            },
            dst.raw(),
            src,
        )
    }
}

impl<
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext,
> PendingFileVenue for El1PendingFamilies<'_, F, C, U, G, Context>
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
impl<F, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame, Context: DispatchContext>
    El1PendingFamilies<'_, F, C, U, G, Context>
{
    fn file_access(&self) -> carrick_el1::substrate::file_notification::FileAccess<'_> {
        match (self.zone.as_ref(), self.frame.slot()) {
            (Some(zone), Some(slot)) => {
                carrick_el1::substrate::file_notification::FileAccess::notified(zone.tables, slot)
            }
            _ => {
                #[cfg(any(test, feature = "host-test"))]
                {
                    carrick_el1::substrate::file_notification::FileAccess::SourceFreeModel
                }
                #[cfg(not(any(test, feature = "host-test")))]
                {
                    carrick_el1::substrate::file_notification::FileAccess::Unavailable
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn try_serve_file_syscall<'a, F, G: SyscallFrame>(
    access: carrick_el1::substrate::file_notification::FileAccess<'a>,
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

pub use file::{InstanceLockPolicy, TryInstanceLock};

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
    let event = match nr {
        64 | 68 => file::FileDataEvent::Modify,
        63 | 67 => file::FileDataEvent::Access,
        _ => file::FileDataEvent::None,
    };
    file::with_data_marks(
        zone_file.inode,
        inotify_table,
        event,
        locks,
        Action::Forward,
        |&moved| moved > 0,
        // SAFETY: forwarded from the caller's contract.
        || unsafe {
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
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn host_loaded_arm_task_keeps_terminal_calls_on_legacy_route() {
        assert!(!arm_process_call_claimed(94, 0, || false), "exit_group");
        assert!(!arm_process_call_claimed(93, 0, || false), "exit");
        assert!(!arm_process_call_claimed(95, 0, || false), "waitid");
        assert!(arm_process_call_claimed(220, 0, || false), "first fork");
        assert!(
            arm_process_call_claimed(94, 0, || true),
            "native child exit"
        );
        assert!(
            arm_process_call_claimed(93, 0, || true),
            "native thread exit"
        );
        assert!(!arm_process_call_claimed(62, 0, || panic!(
            "ordinary lseek queried registry"
        )));
    }

    #[test]
    fn refused_native_termination_never_returns_to_el0() {
        assert!(arm_process_refusal_must_abort(94), "exit_group");
        assert!(arm_process_refusal_must_abort(93), "exit");
        assert!(
            !arm_process_refusal_must_abort(260),
            "waitid may report errno"
        );
    }

    #[test]
    fn refused_owned_process_return_retains_one_completed_boundary() {
        let mut frame = TrapFrame::default();
        frame.x[8] = 435;
        frame.x[0] = 0xfeed;
        let tasks = [CurrentTask::new()];
        let counters = Counters::default();
        assert_eq!(
            refuse_owner_process_call(&mut frame, &counters, &tasks),
            Action::ServedWithWork
        );
        assert_eq!(frame.x[0] as i64, -38);
        assert_eq!(tasks[0].linux.orig_arg0.load(Ordering::Relaxed), 0xfeed);
        assert_eq!(
            tasks[0].linux.take_served_boundary(),
            Some(carrick_el1_abi::ServedBoundary::Completed)
        );
        assert_eq!(tasks[0].linux.take_served_boundary(), None);
        assert_eq!(counters.served[435].load(Ordering::Relaxed), 1);
    }

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
                task.execution.generation.store(
                    carrick_el1_abi::SnapshotGeneration::from_raw(12),
                    Ordering::Release,
                );
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
                tasks[0].set(
                    carrick_el1_abi::El1TaskId::from_linux_tid(41),
                    carrick_el1_abi::SnapshotGeneration::from_raw(11),
                    5,
                );
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
                    process: None::<&mut dyn carrick_personality_linux::lifecycle::ProcessNative>,
                    source: None,
                    anonymous: None,
                    cache_lookup: |_| core::ptr::null_mut(),
                };
                assert_eq!(
                    carrick_personality_linux::dispatch::dispatch(178, u64::MAX, &mut pending),
                    carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
                );
                assert_eq!(frame.x[0], 0xfeed);
                assert_eq!(tasks[0].linux.orig_arg0.load(Ordering::Relaxed), 77);
                assert_eq!(counters.served[178].load(Ordering::Relaxed), 0);
                assert_eq!(tasks[0].linux.served_word(), 0);
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
                    0 => task.execution.generation.store(
                        carrick_el1_abi::SnapshotGeneration::from_raw(12),
                        Ordering::Release,
                    ),
                    1 => {
                        let mm = self.identity.mm;
                        let address = (0x2000..0x2400)
                            .step_by(4)
                            .find(|address| {
                                ZoneTables::bucket_of_with_context(mm, *address)
                                    != ZoneTables::bucket_of_with_context(mm, 0x1000)
                            })
                            .unwrap();
                        let guard = self
                            .zone
                            .lock(
                                ZoneTables::bucket_of_with_context(mm, address),
                                &BoundedSpin(1024),
                            )
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
                            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
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
                            carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
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
                            process: None::<
                                &mut dyn carrick_personality_linux::lifecycle::ProcessNative<
                                    carrick_el1_abi::Aarch64ParkedContext,
                                >,
                            >,
                            source: None,
                            anonymous: None,
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
                        assert_eq!(tasks[0].linux.served_word(), 0);
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
        assert_eq!(action, Action::Served);
        if !cfg!(feature = "allocator-test-control") {
            assert_eq!(frame.x[0] as i64, -38);
            assert_eq!(counters.refused[512].load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn unconfigured_host_aperture_refuses_unported_calls_and_counts() {
        let mut frame = TrapFrame::default();
        let counters = Counters::default();

        frame.x[8] = 64; // write
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 1);
        assert_eq!(counters.served[64].load(Ordering::Relaxed), 0);

        frame.x[8] = 172; // getpid
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Served);
        assert_eq!(frame.x[0] as i64, -38);
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.refused[172].load(Ordering::Relaxed), 1);
        assert_eq!(counters.forwarded[64].load(Ordering::Relaxed), 1);

        // Out-of-bounds syscall nr
        frame.x[8] = 999;
        let action = dispatch_syscall(&mut frame, &counters);
        assert_eq!(action, Action::Served);
        assert_eq!(counters.refused[512].load(Ordering::Relaxed), 1);
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
        assert_eq!(action, Action::Served);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
    }
}
