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

use carrick_personality_linux::native_host_file::ppoll_timeout_ms;

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
    fn may_serve_poll(&self) -> bool {
        self.x[8] == carrick_syscall_abi::nr::PPOLL.raw()
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
            use super::native_process_runtime::NativeThreadGroupOwner;

            let (nr, flags) = (frame.x[8], frame.x[0]);
            // Without a published lifecycle no owner can retain this thread.
            let unowned = arm_process_call_claimed(nr, flags, || NativeThreadGroupOwner::Unowned);
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
                    || arm_thread_group_owner(zone, task, page),
                    carrick_el1_abi::Lifecycle::live(page),
                )
            };
            let mut saved = alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
            sched::ThreadCpu::save(
                &mut sched::HardwareCpu,
                frame,
                &mut saved,
                sched::CpuExitCause::Svc,
            );
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
                Ok(route) => {
                    resolve_arm_process_route(route, frame, counters, current_tasks, refused)
                }
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
    ipc: Option<&ipc::IpcVenue<'static>>,
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
    super::aarch64_process::with_process_entry(
        source,
        service.task,
        native,
        ttbr0,
        page,
        control,
        service,
        |process| {
            // Dispatch may park this owner and install a peer's frame. The
            // final EL0 checkpoint re-enters that selected owner only after
            // this pre-dispatch entry has released its borrow.
            dispatch_syscall_with_native(
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
            )
        },
    )
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn arm_process_call_claimed(
    nr: u64,
    flags: u64,
    owner: impl FnOnce() -> super::native_process_runtime::NativeThreadGroupOwner,
) -> bool {
    use super::native_process_runtime::NativeThreadGroupOwner;

    // Only a ring-owned fork child's execve and execveat are the native
    // owner's. A root or host-loaded task execs through the host with its own
    // live cwd, credentials, executable and descriptor table. A fork child
    // has no host task: its execveat is served by the native exec service,
    // which resolves a named descriptor in the child's ring table (#1530).
    nr == 435
        || (nr == 220 && flags & 0x0001_0000 == 0)
        || match nr {
            221 | 281 => owner() == NativeThreadGroupOwner::ForkChild,
            260 | 93 | 94 | 95 | 58 | 139 => owner() != NativeThreadGroupOwner::Unowned,
            _ => false,
        }
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
    owner: impl FnOnce() -> super::native_process_runtime::NativeThreadGroupOwner,
    live: u32,
) -> bool {
    !(nr == carrick_personality_linux::lifecycle::SYS_EXIT as u64 && live > 1)
        && arm_process_call_claimed(nr, flags, owner)
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn resolve_arm_process_route(
    route: carrick_personality_linux::dispatch::CompletionRoute,
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    refuse_forward: impl FnOnce() -> bool,
) -> Action {
    match route {
        carrick_personality_linux::dispatch::CompletionRoute::HostCustody => Action::HostCustody,
        carrick_personality_linux::dispatch::CompletionRoute::NativeService => Action::Forward,
        carrick_personality_linux::dispatch::CompletionRoute::Served => Action::Served,
        carrick_personality_linux::dispatch::CompletionRoute::WithWork => Action::ServedWithWork,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended => Action::Idle,
        carrick_personality_linux::dispatch::CompletionRoute::Forward => {
            if refuse_forward() {
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

/// The exact admitted owner kind for this thread's group at any address.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn arm_thread_group_owner(
    zone: &ZoneTables,
    task: &CurrentTask,
    page: &carrick_el1_abi::ThreadLifecyclePage,
) -> super::native_process_runtime::NativeThreadGroupOwner {
    task.visible_pid().map_or(
        super::native_process_runtime::NativeThreadGroupOwner::Unowned,
        |pid| super::aarch64_process::registry().thread_group_owner(zone, page, pid),
    )
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
    ipc: Option<&ipc::IpcVenue<'static>>,
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
pub fn dispatch_entry(
    frame: &mut TrapFrame,
    counters: &Counters,
    owner_wait: &mut Option<carrick_el1_abi::PortalOwnerWait>,
) -> Action {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    if matches!(frame.esr, 0xfffc..=0xfffe) {
        return arm_signal_user_return(frame);
    }
    let action = if frame.esr == 0 {
        dispatch_irq(frame, counters)
    } else {
        match (frame.esr >> 26) & 0x3f {
            0x20 | 0x24 => dispatch_fault(frame, counters, owner_wait),
            0x15 => dispatch_syscall(frame, counters),
            // Any other EL0 synchronous exception (BRK, step, undefined
            // instruction, alignment, FP) is never a syscall (#1502). It
            // forwards unserved: a native owner captures it as its exception
            // service; a host task's leaves through `hvc #2` as before.
            _ => Action::Forward,
        }
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    return final_user_return(frame, action, arm_signal_user_return);
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    action
}

/// Re-enter the selected owner after dispatch and scheduler continuation settle.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn final_user_return(
    frame: &mut TrapFrame,
    action: Action,
    checkpoint: impl FnOnce(&mut TrapFrame) -> Action,
) -> Action {
    if matches!(action, Action::Served | Action::ServedWithWork)
        && (frame.esr == 0 || matches!((frame.esr >> 26) & 0x3f, 0x15 | 0x20 | 0x24))
    {
        return match checkpoint(frame) {
            // Signal publication must not erase an already committed entry's
            // remaining work. The capture boundary still owns that ledger.
            Action::Served => action,
            outcome => outcome,
        };
    }
    action
}

/// Capture only after the final descriptor drain has selected its boundary.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn capture_native_service_exit(
    frame: &mut TrapFrame,
    action: Action,
    wait: Option<carrick_core_abi::PortalOwnerWait>,
    counters: &Counters,
) -> Action {
    if matches!(action, Action::Forward | Action::ServedWithWork)
        && let Some(owned) = arm_native_service_exit(frame, action, wait, counters)
    {
        return owned;
    }
    action
}

/// Where a native-owned syscall goes when its owner claimed none of it.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnclaimedNativeSyscall {
    /// A root (host-loaded) or unadmitted task keeps its existing route: an
    /// unclaimed exec leaves for its host task, any other call is captured
    /// as a crossing for the carrier.
    HostRoute,
    /// A ring-owned fork child (or its exec successor) has no host task, so a
    /// raw host exit has no one to serve it: the executor would fail and the
    /// carrier with it (#1530). A crossing could only be refused by the
    /// carrier. Ring-first: counted ENOSYS, in ring, counted once here.
    CountedEnosys,
}

/// The one place that decides an unclaimed native syscall's route, so a
/// future unclaimed ordinal is covered too. Both of an owned native entry's
/// unclaimed exits ask it: an unclaimed exec ([`arm_native_service_exit`])
/// and a syscall no ring stage served ([`native_unstaged_exit`]).
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn unclaimed_native_syscall(
    owner: super::native_process_runtime::NativeThreadGroupOwner,
) -> UnclaimedNativeSyscall {
    use super::native_process_runtime::NativeThreadGroupOwner;
    match owner {
        NativeThreadGroupOwner::ForkChild => UnclaimedNativeSyscall::CountedEnosys,
        NativeThreadGroupOwner::Root | NativeThreadGroupOwner::Unowned => {
            UnclaimedNativeSyscall::HostRoute
        }
    }
}

/// Answer an unclaimed native syscall with a counted ENOSYS in ring.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn refuse_unclaimed_native_syscall(frame: &mut TrapFrame, counters: &Counters) -> Action {
    let ordinal = carrick_guest_arch::NativeOrdinal::new(frame.x[8]);
    // Only CountedEnosys reaches this boundary: its admitted owner is a
    // fork child, including an exec successor with the same lineage.
    counters.record_refusal(
        ordinal,
        carrick_core_abi::service::ServiceOrigin::Descendant,
        carrick_el1_abi::RefusalVenue::Ring,
    );
    if let Some(served) = counters.served.get(ordinal.raw() as usize) {
        served.fetch_add(1, Ordering::Relaxed);
    }
    frame.x[0] = carrick_syscall_abi::LINUX_ENOSYS.guest_retval() as u64;
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        arm_signal_user_return(frame)
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        Action::Served
    }
}

/// How an owned native entry that no ring stage served leaves the ring.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[derive(Debug, Eq, PartialEq)]
pub(super) enum NativeUnstagedExit {
    /// Answered in ring ([`refuse_unclaimed_native_syscall`]); return to EL0.
    Refused(Action),
    /// Park on this operation for the carrier.
    Operation(carrick_core_abi::service::ServiceOperation),
    /// A ring-owned family forwarded a call it guarantees to finish (an
    /// admitted futex wake) for a task with no host route: no server exists
    /// for its forward. Fatal
    /// ([`NativeInvariant::OwnedFamilyForward`]), never a silent errno.
    OwnedFamilyForward,
    /// No operation describes this boundary: the entry keeps its action.
    Declined,
}

/// The final capture of an owned native entry no stage served. An unserved
/// syscall asks [`unclaimed_native_syscall`] before it may become a
/// crossing, so the in-ring refusal is the single exit for a fork child's
/// unclaimed call and is counted once, never also as a carrier refusal.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn native_unstaged_exit(
    frame: &mut TrapFrame,
    state: &carrick_el1_abi::LinuxTaskState,
    action: Action,
    owner: impl FnOnce() -> super::native_process_runtime::NativeThreadGroupOwner,
    counters: &Counters,
) -> NativeUnstagedExit {
    if action == Action::Forward
        && (frame.esr >> 26) & 0x3f == 0x15
        && unclaimed_native_syscall(owner()) == UnclaimedNativeSyscall::CountedEnosys
    {
        // The counted ENOSYS answers an unported call or a declined one. An
        // admitted futex wake always finishes in ring; a forward of one
        // would lose the wake (#1941). A futex wait may decline and keeps
        // the counted refusal.
        let mut args = [0; 6];
        args.copy_from_slice(&frame.x[..6]);
        if carrick_personality_linux::sched::ring_owned_futex(
            carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
            args,
        ) {
            return NativeUnstagedExit::OwnedFamilyForward;
        }
        return NativeUnstagedExit::Refused(refuse_unclaimed_native_syscall(frame, counters));
    }
    native_service_operation(frame, state, action)
        .map_or(NativeUnstagedExit::Declined, NativeUnstagedExit::Operation)
}

/// The entry's last step (#1100): seal its decision into the vector's
/// return word. An idle exit vacates the slot here
/// ([`sched::El1Exit::seal`]), whichever producer chose it.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub fn seal_entry_exit_with(
    frame: &TrapFrame,
    action: Action,
    zone: &ZoneTables,
    cpu: &mut impl sched::ThreadCpu,
) -> sched::El1Exit {
    sched::El1Exit::seal(action, zone, SlotId::from_index(frame.slot as usize), cpu)
}

/// [`seal_entry_exit_with`] on this vCPU and the image's zone tables.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn seal_entry_exit(frame: &TrapFrame, action: Action) -> sched::El1Exit {
    // SAFETY: the EL1 zone tables are fixed image-lifetime ABI storage.
    let zone: &'static ZoneTables = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
    seal_entry_exit_with(frame, action, zone, &mut sched::HardwareCpu)
}

/// Interpret the final entry boundary without granting custody. Only the
/// authenticated native owner below may publish the resulting operation.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn native_service_operation(
    frame: &mut TrapFrame,
    state: &carrick_el1_abi::LinuxTaskState,
    action: Action,
) -> Option<carrick_core_abi::service::ServiceOperation> {
    use carrick_core_abi::service::{NativeException, NativeExceptionKind, ServiceOperation};
    use carrick_guest_arch::{Access, FaultInfo, NativeOrdinal, UserVa};
    use carrick_sched_core::object_wait::OwnerEntry;
    if action == Action::ServedWithWork {
        let entry = match state.served_word() {
            carrick_el1_abi::SERVED_WAKES_OWED => OwnerEntry::Syscall,
            carrick_el1_abi::SERVED_FORWARD_WORK => OwnerEntry::Exception,
            // Metadata commits require their own operation, never a replay
            // that could repeat an already visible effect.
            _ => return None,
        };
        match state.take_served_boundary()? {
            carrick_el1_abi::ServedBoundary::Completed => {}
            carrick_el1_abi::ServedBoundary::ForwardOriginal { x0 } => {
                frame.x[0] = x0;
                frame.elr = frame.elr.checked_sub(4)?;
            }
            carrick_el1_abi::ServedBoundary::ReplayOriginal { .. } => return None,
        }
        // This operation owns the work until its exact carrier reply. Do not
        // manufacture the vector's independent host-work doorbell: a reply
        // consumed in ring would otherwise leave that doorbell armed forever.
        return Some(ServiceOperation::CarrierWork { entry });
    }
    if action != Action::Forward {
        return None;
    }
    if frame.esr == 0 {
        return state
            .has_pending_host_work()
            .then_some(ServiceOperation::CarrierWork {
                entry: OwnerEntry::Exception,
            });
    }
    match (frame.esr >> 26) & 0x3f {
        kind @ (0x20 | 0x24) => Some(ServiceOperation::Fault(FaultInfo {
            address: UserVa::new(frame.far),
            access: if kind == 0x20 {
                Access::Execute
            } else if frame.esr & (1 << 6) != 0 {
                Access::Write
            } else {
                Access::Read
            },
            present: !(0x04..=0x07).contains(&(frame.esr & 0x3f)),
        })),
        0x15 => Some(ServiceOperation::Crossing {
            ordinal: NativeOrdinal::new(frame.x[8]),
        }),
        0x3c => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::Breakpoint,
            address: UserVa::new(frame.elr),
        })),
        0x32 | 0x33 => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::SingleStep,
            address: UserVa::new(frame.elr),
        })),
        0x30 | 0x31 | 0x34 | 0x35 => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::HardwareBreakpoint,
            address: UserVa::new(frame.elr),
        })),
        0x00 | 0x0e => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::UndefinedInstruction,
            address: UserVa::new(frame.elr),
        })),
        0x22 | 0x26 => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::Alignment,
            address: UserVa::new(frame.far),
        })),
        0x07 | 0x2c => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::FloatingPoint,
            address: UserVa::new(frame.elr),
        })),
        // Every other EL0 synchronous exception the vector delivers (a
        // trapped `wfi`/`wfe`, SVE/SME access, PAC, BTI, FPAC, ...): Linux
        // answers an EL0 exception it has no handler for with SIGILL
        // (ILL_ILLOPC) at the PC. Never `None`: a native process has no host
        // task, so a host exit would kill its executor (#1502).
        _ => Some(ServiceOperation::Exception(NativeException {
            kind: NativeExceptionKind::UndefinedInstruction,
            address: UserVa::new(frame.elr),
        })),
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn native_exec_stage(frame: &TrapFrame, task: &CurrentTask) -> Option<NativeExecStage> {
    if (frame.esr >> 26) & 0x3f != 0x15 {
        return None;
    }
    let request = match frame.x[8] {
        221 => crate::exec_stage::ExecStageRequest {
            call: carrick_core_abi::service::ExecCall::Execve,
            path: frame.x[0],
            argv: frame.x[1],
            envp: frame.x[2],
        },
        281 => crate::exec_stage::ExecStageRequest {
            call: carrick_core_abi::service::ExecCall::Execveat {
                dirfd: frame.x[0] as i32,
                flags: frame.x[4] as u32,
            },
            path: frame.x[1],
            argv: frame.x[2],
            envp: frame.x[3],
        },
        _ => return None,
    };
    native_exec_stage_request(task, &file::HardwareValidator, request)
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
enum NativeExecStage {
    Payload(alloc::boxed::Box<[u8]>),
    Fault(carrick_guest_arch::FaultInfo),
    Failed(carrick_syscall_abi::LinuxErrno),
}

/// The EL0 data-abort syndrome a staging copy would have taken: a read or a
/// write translation fault, or a write permission fault on a present page
/// (COW), so the ordinary owner fault selector resolves it exactly.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native_stage_fault_syndrome(fault: carrick_guest_arch::FaultInfo) -> u64 {
    const DATA_ABORT_EL0: u64 = 0x24 << 26;
    const WRITE: u64 = 1 << 6;
    match fault.access {
        carrick_guest_arch::Access::Write
            if file::MemoryValidator::readable_bytes(
                &file::HardwareValidator,
                fault.address.raw(),
                1,
            ) == 1 =>
        {
            DATA_ABORT_EL0 | WRITE | 0x0f
        }
        carrick_guest_arch::Access::Write => DATA_ABORT_EL0 | WRITE | 0x07,
        _ => DATA_ABORT_EL0 | 0x04,
    }
}

/// A staged host-file request, boxed so the service exit frame (a retained
/// EL1 stack chain) does not carry it by value.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct StagedHostFile {
    record: alloc::boxed::Box<[u8]>,
    output: Option<carrick_personality_linux::native_host_file::HostFileOutput>,
    resolves_path: bool,
    map: Option<carrick_personality_linux::native_host_file::NativeMapKey>,
    chdir: bool,
}

/// One staged native service request, before its owner publishes it.
/// Stage only a bounded accessible prefix; the exact-MM owner prepares COW
/// and authenticates it before entropy is requested from the carrier.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn native_entropy_stage(
    frame: &TrapFrame,
) -> (
    carrick_guest_arch::UserVa,
    usize,
    crate::native_process_runtime::NativeEntropyFlags,
    carrick_guest_arch::GuestLen,
) {
    crate::native_process_runtime::native_entropy_stage(
        crate::native_process_runtime::NativeEntropyArgs {
            address: carrick_guest_arch::UserVa::new(frame.x[0]),
            length: carrick_guest_arch::GuestLen::new(frame.x[1]),
            flags: crate::native_process_runtime::NativeEntropyFlags::from_bits_retain(
                frame.x[2] as u32,
            ),
        },
    )
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
enum NativeServiceStage {
    Exec(alloc::boxed::Box<[u8]>),
    HostFile(alloc::boxed::Box<StagedHostFile>),
    Entropy {
        address: carrick_guest_arch::UserVa,
        capacity: usize,
        flags: crate::native_process_runtime::NativeEntropyFlags,
        requested: carrick_guest_arch::GuestLen,
    },
    Fault(carrick_guest_arch::FaultInfo),
    Return(i64),
    Operation,
}

struct HostFileCopy<'a, V: file::MemoryValidator>(file::ValidatedCopy<'a, V>);

impl<V: file::MemoryValidator> carrick_personality_linux::native_host_file::HostFileUser
    for HostFileCopy<'_, V>
{
    fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool {
        file::UserCopy::copy_in(&mut self.0, dst, src)
    }
    fn writable(&mut self, dst: u64, len: usize) -> usize {
        self.0.validator.writable_bytes(dst, len)
    }
}

/// Stage an ISA-decoded host-file call against the caller's ring namespace.
/// Both exception venues use the same validated user-copy implementation;
/// transports retain the resulting record until its service completes.
#[inline(never)]
pub fn stage_native_host_file<V: file::MemoryValidator>(
    call: carrick_personality_linux::native_host_file::HostFileCall,
    task: &CurrentTask,
    validator: &V,
    namespace: &mut carrick_personality_linux::native_host_file::NativeNamespace<'_>,
) -> Option<carrick_personality_linux::native_host_file::HostFileStage> {
    let mut user = HostFileCopy(file::ValidatedCopy { task, validator });
    carrick_personality_linux::native_host_file::stage(call, namespace, &mut user)
}

/// Route a native SVC through the host-file venue. `None` keeps the call on
/// its existing route; the descriptor is resolved in the caller's own ring
/// namespace by `descriptor`.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
pub(super) fn native_host_file_stage<V: file::MemoryValidator>(
    frame: &TrapFrame,
    task: &CurrentTask,
    validator: &V,
    table: [u64; 3],
    mut descriptor: impl FnMut(i32) -> Option<NativeDescriptor>,
    releases: &mut dyn FnMut(&mut [carrick_core_abi::host_file::MapSourceReply]) -> usize,
) -> Option<carrick_personality_linux::native_host_file::HostFileStage> {
    use carrick_personality_linux::native_host_file::{HostFileCall, NativeNamespace};
    if (frame.esr >> 26) & 0x3f != 0x15 {
        return None;
    }
    // AArch64 native numbers are the canonical Linux numbers.
    let call = HostFileCall::decode(
        carrick_syscall_abi::CanonicalNr::new(frame.x[8]),
        &[
            frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
        ],
    )?;
    let mut namespace = NativeNamespace {
        table,
        resolve: &mut descriptor,
        releases,
    };
    stage_native_host_file(call, task, validator, &mut namespace)
}

/// The byte sources the caller's reservation owner retired, for the
/// carrier to release with this private-mapping request.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn native_source_releases<C: Copy + Send + Sync + zerocopy::FromZeros>(
    task: &CurrentTask,
    access: carrick_sched_core::spaces::notification::SpaceAccess<'_, C>,
    slot: u32,
    out: &mut [carrick_core_abi::host_file::MapSourceReply],
) -> usize {
    let mut taken = [(core::num::NonZeroU64::MIN, core::num::NonZeroU64::MIN);
        carrick_core_abi::host_file::MAX_MAP_RELEASES];
    let limit = out.len().min(taken.len());
    let count = memory::take_native_source_releases(
        task,
        access,
        memory::reservations::shared_guest(),
        slot,
        &mut taken[..limit],
    );
    for (dst, (handle, generation)) in out.iter_mut().zip(&taken[..count]) {
        *dst = carrick_core_abi::host_file::MapSourceReply {
            handle: *handle,
            generation: *generation,
        };
    }
    count
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
use carrick_personality_linux::native_host_file::NativeDescriptor;

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
struct ExecStageCopy<'a, V: file::MemoryValidator> {
    inner: file::ValidatedCopy<'a, V>,
    fault: Option<u64>,
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
impl<V: file::MemoryValidator> file::UserCopy for ExecStageCopy<'_, V> {
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
        self.inner.copy_out(dst_va, src)
    }

    fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
        let copied = self.inner.copy_in(dst, src_va);
        if !copied && self.fault.is_none() {
            self.fault = Some(src_va);
        }
        copied
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn native_exec_stage_request<V: file::MemoryValidator>(
    task: &CurrentTask,
    validator: &V,
    request: crate::exec_stage::ExecStageRequest,
) -> Option<NativeExecStage> {
    let mut user = ExecStageCopy {
        inner: file::ValidatedCopy { task, validator },
        fault: None,
    };
    let staged = crate::exec_stage::stage_exec_payload(&mut user, request);
    Some(match (staged, user.fault) {
        (Ok(payload), _) => NativeExecStage::Payload(payload),
        (Err(errno), Some(address)) if errno == carrick_syscall_abi::LINUX_EFAULT => {
            NativeExecStage::Fault(carrick_guest_arch::FaultInfo {
                address: carrick_guest_arch::UserVa::new(address),
                access: carrick_guest_arch::Access::Read,
                present: false,
            })
        }
        (Err(errno), _) => NativeExecStage::Failed(errno),
    })
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn refuse_traced_native_exec(
    frame: &mut TrapFrame,
    task: &CurrentTask,
    counters: &Counters,
    child: impl FnOnce() -> bool,
) -> bool {
    if !matches!(frame.x[8], 221 | 281) || !task.ptrace_traced() {
        return false;
    }
    let nr = frame.x[8] as usize;
    counters.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
        if child() {
            carrick_core_abi::service::ServiceOrigin::Descendant
        } else {
            carrick_core_abi::service::ServiceOrigin::Initial
        },
        carrick_el1_abi::RefusalVenue::Ring,
    );
    counters.served[nr].fetch_add(1, Ordering::Relaxed);
    frame.x[0] = carrick_syscall_abi::LINUX_EPERM.guest_retval() as u64;
    true
}

/// Settle a host-file staging answer in ring. Staging can refuse before a
/// carrier request exists, so its ENOSYS belongs to the ring census too.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn native_host_file_return(
    result: i64,
    ordinal: carrick_guest_arch::NativeOrdinal,
    counters: &Counters,
    child: impl FnOnce() -> bool,
) -> i64 {
    if result == carrick_syscall_abi::LINUX_ENOSYS.guest_retval() {
        counters.record_refusal(
            ordinal,
            if child() {
                carrick_core_abi::service::ServiceOrigin::Descendant
            } else {
                carrick_core_abi::service::ServiceOrigin::Initial
            },
            carrick_el1_abi::RefusalVenue::Ring,
        );
        if let Some(served) = counters.served.get(ordinal.raw() as usize) {
            served.fetch_add(1, Ordering::Relaxed);
        }
    }
    result
}

/// Capture the exception while its native owner still owns the trap words.
/// The host receives a selector only after this continuation has parked.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
fn arm_native_service_exit(
    frame: &mut TrapFrame,
    action: Action,
    wait: Option<carrick_core_abi::PortalOwnerWait>,
    counters: &Counters,
) -> Option<Action> {
    use super::native_process_runtime::NativeResume;
    let task = carrick_el1_abi::current_task_guest(frame.slot as usize)?;
    let slot = SlotId::from_index(frame.slot as usize)?;
    let zone: &'static ZoneTables = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
    let (page, control) = task.lifecycle_refs()?;
    let entry = if (frame.esr >> 26) & 0x3f == 0x15 {
        carrick_sched_core::object_wait::OwnerEntry::Syscall
    } else {
        carrick_sched_core::object_wait::OwnerEntry::Exception
    };
    if !super::native_process_runtime::native_entry_owned(
        carrick_el1_abi::BornInZoneSource { zone, slot },
        task,
        page,
        control,
        entry,
    ) {
        return None;
    }
    // Only a fork child's execve and execveat are staged for the native exec
    // service; a root's exec keeps the host route and its live cwd,
    // credentials, executable and descriptor table.
    if (frame.esr >> 26) & 0x3f == 0x15
        && matches!(frame.x[8], 221 | 281)
        && !arm_process_call_claimed(frame.x[8], 0, || arm_thread_group_owner(zone, task, page))
    {
        return match unclaimed_native_syscall(arm_thread_group_owner(zone, task, page)) {
            UnclaimedNativeSyscall::HostRoute => None,
            UnclaimedNativeSyscall::CountedEnosys => {
                Some(refuse_unclaimed_native_syscall(frame, counters))
            }
        };
    }
    let child = || {
        arm_thread_group_owner(zone, task, page)
            == super::native_process_runtime::NativeThreadGroupOwner::ForkChild
    };
    if refuse_traced_native_exec(frame, task, counters, child) {
        return Some(arm_signal_user_return(frame));
    }
    let mut service_wait = wait;
    let (operation, exec_payload, host_file, entropy, retry_exec_stage) = {
        let staged = match native_exec_stage(frame, task) {
            Some(NativeExecStage::Payload(payload)) => NativeServiceStage::Exec(payload),
            Some(NativeExecStage::Failed(errno)) => {
                NativeServiceStage::Return(errno.guest_retval())
            }
            Some(NativeExecStage::Fault(fault)) => NativeServiceStage::Fault(fault),
            // Only an unserved call crosses. A call served with owed host
            // work first settles that work (CarrierWork) and is replayed;
            // staging it here would pre-empt the settlement forever.
            None if action != Action::Forward => NativeServiceStage::Operation,
            None if frame.x[8] == 278 => {
                let (address, capacity, flags, requested) = native_entropy_stage(frame);
                NativeServiceStage::Entropy {
                    address,
                    capacity,
                    flags,
                    requested,
                }
            }
            None => match ipc::guest_venue(frame.slot as u32).and_then(|venue| {
                let table = ipc::native_table(&venue, task)?;
                let access = carrick_el1::substrate::sched::object_wait::space_access(zone, slot);
                let lock_slot = frame.slot as u32;
                native_host_file_stage(
                    frame,
                    task,
                    &file::HardwareValidator,
                    table,
                    |fd| ipc::native_descriptor(&venue, table, fd),
                    &mut |out| native_source_releases(task, access, lock_slot, out),
                )
            }) {
                Some(carrick_personality_linux::native_host_file::HostFileStage::Request {
                    record,
                    output,
                    resolves_path,
                    map,
                    chdir,
                }) => NativeServiceStage::HostFile(alloc::boxed::Box::new(StagedHostFile {
                    record,
                    output,
                    resolves_path,
                    map,
                    chdir,
                })),
                Some(carrick_personality_linux::native_host_file::HostFileStage::Returned(
                    result,
                )) => NativeServiceStage::Return(native_host_file_return(
                    result.raw(),
                    carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
                    counters,
                    child,
                )),
                Some(carrick_personality_linux::native_host_file::HostFileStage::InRingReply {
                    output,
                    bytes,
                }) => {
                    // Staging proved the destination writable; the ring
                    // copies its own answer.
                    let mut copy = file::ValidatedCopy {
                        task,
                        validator: &file::HardwareValidator,
                    };
                    NativeServiceStage::Return(
                        if file::UserCopy::copy_out(&mut copy, output.address, &bytes) {
                            0
                        } else {
                            carrick_syscall_abi::LINUX_EFAULT.guest_retval()
                        },
                    )
                }
                Some(carrick_personality_linux::native_host_file::HostFileStage::Fault {
                    address,
                    access,
                }) => NativeServiceStage::Fault(carrick_guest_arch::FaultInfo {
                    address: carrick_guest_arch::UserVa::new(address),
                    access,
                    // A write to a readable page is a permission (COW) fault.
                    present: access == carrick_guest_arch::Access::Write
                        && file::MemoryValidator::readable_bytes(
                            &file::HardwareValidator,
                            address,
                            1,
                        ) == 1,
                }),
                Some(carrick_personality_linux::native_host_file::HostFileStage::InRing) => {
                    // An in-zone object the ring does not serve yet never
                    // exits to the host: counted ENOSYS here, in ring.
                    NativeServiceStage::Return(native_host_file_return(
                        carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
                        carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
                        counters,
                        child,
                    ))
                }
                None => NativeServiceStage::Operation,
            },
        };
        match staged {
            NativeServiceStage::Exec(payload) => (None, Some(payload), None, None, false),
            NativeServiceStage::HostFile(staged) => (None, None, Some(staged), None, false),
            NativeServiceStage::Entropy {
                address,
                capacity,
                flags,
                requested,
            } => (
                None,
                None,
                None,
                Some((address, capacity, flags, requested)),
                false,
            ),
            NativeServiceStage::Return(result) => {
                frame.x[0] = result as u64;
                return Some(arm_signal_user_return(frame));
            }
            NativeServiceStage::Fault(fault) => {
                // `AT S1E0R` reports an inherited sparse page without taking
                // an EL0 abort. Feed that exact read through the ordinary
                // owner fault selector, retaining the syscall frame for retry.
                let mut synthetic = *frame;
                synthetic.esr = native_stage_fault_syndrome(fault);
                synthetic.far = fault.address.raw();
                let mut fault_wait = None;
                match super::cow_resolver::dispatch_fault(&mut synthetic, counters, &mut fault_wait)
                {
                    Action::Served => {
                        // Staging made no descriptor/IPC effect. Re-enter the
                        // ring at the same SVC rather than staging InRing into
                        // ENOSYS after the owner resolved its destination.
                        frame.elr = frame.elr.wrapping_sub(4);
                        return Some(Action::Served);
                    }
                    Action::Forward | Action::ServedWithWork => {
                        service_wait = fault_wait;
                        (
                            Some(carrick_core_abi::service::ServiceOperation::Fault(fault)),
                            None,
                            None,
                            None,
                            true,
                        )
                    }
                    Action::Idle | Action::HostCustody => {
                        invalid_completion(NativeInvariant::EntryBinding)
                    }
                }
            }
            NativeServiceStage::Operation => match native_unstaged_exit(
                frame,
                &task.linux,
                action,
                || arm_thread_group_owner(zone, task, page),
                counters,
            ) {
                NativeUnstagedExit::Refused(refused) => return Some(refused),
                NativeUnstagedExit::Operation(operation) => {
                    (Some(operation), None, None, None, false)
                }
                NativeUnstagedExit::Declined => return None,
                NativeUnstagedExit::OwnedFamilyForward => {
                    invalid_completion(NativeInvariant::OwnedFamilyForward)
                }
            },
        }
    };
    // This CPU still exclusively owns its portal slot. Bind its selection
    // before park, so even a delayed first intake cannot steal a successor.
    let fault_sequence =
        if let Some(carrick_core_abi::service::ServiceOperation::Fault(fault)) = operation {
            // SAFETY: fixed initialized ABI region of this carrier.
            let portal = unsafe {
                &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
            };
            portal
                .grant(frame.slot as usize)?
                .native_fault_sequence(task.mm.key.load(Ordering::Acquire), fault.address.raw())
        } else {
            None
        };
    let mut saved = alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    sched::ThreadCpu::save(
        &mut sched::HardwareCpu,
        frame,
        &mut saved,
        sched::CpuExitCause::Svc,
    );
    let mut service = super::aarch64_process::Aarch64NativeProcessService::new(task, slot)
        .unwrap_or_else(|_| invalid_completion(NativeInvariant::EntryBinding));
    let (result, phase) = super::aarch64_process::with_process_entry(
        carrick_el1_abi::BornInZoneSource { zone, slot },
        task,
        &saved.native,
        carrick_el1::isa::aarch64::hardware_live_ttbr(),
        page,
        control,
        &mut service,
        |process| {
            let exit = if matches!(
                operation,
                Some(carrick_core_abi::service::ServiceOperation::CarrierWork { .. })
            ) {
                super::native_process_runtime::NativeServiceExit::CarrierWork
            } else {
                super::native_process_runtime::NativeServiceExit::Bridge
            };
            let result = if let Some(payload) = exec_payload {
                if service_wait.is_some() {
                    Err(super::native_process_runtime::NativeProcessError::Quarantined)
                } else {
                    // The exec service resolves a descriptor `execveat`
                    // names in the caller's own ring table (#1530), read
                    // through the stable owned-table authority: an unrelated
                    // table-map update must not read as "no table" (ENOSYS).
                    let table = ipc::guest_venue(frame.slot as u32)
                        .and_then(|venue| ipc::native_exec_table(venue.tables, task));
                    process.begin_exec_service(
                        payload,
                        table,
                        crate::native_process_runtime::NativeServiceCall::new(
                            carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
                            counters,
                        ),
                    )
                }
            } else if let Some((address, capacity, flags, requested)) = entropy {
                process.begin_entropy_service(address, capacity, flags, requested)
            } else if let Some(staged) = host_file {
                if service_wait.is_some() {
                    Err(super::native_process_runtime::NativeProcessError::Quarantined)
                } else {
                    let StagedHostFile {
                        record,
                        output,
                        resolves_path,
                        map,
                        chdir,
                    } = *staged;
                    process.begin_host_file_service(
                        record,
                        output,
                        resolves_path,
                        map,
                        chdir,
                        crate::native_process_runtime::NativeServiceCall::new(
                            carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
                            // SAFETY: this in-ring path retains the fixed ABI
                            // mapping for the lifetime of every continuation.
                            unsafe { &*(carrick_el1_abi::EL1_COUNTERS_BASE as *const Counters) },
                        ),
                    )
                }
            } else if retry_exec_stage {
                match operation {
                    Some(carrick_core_abi::service::ServiceOperation::Fault(fault)) => {
                        process.begin_exec_stage_fault_service(fault, fault_sequence, service_wait)
                    }
                    _ => Err(super::native_process_runtime::NativeProcessError::Quarantined),
                }
            } else if let Some(operation) = operation {
                if let Some(wait) = service_wait {
                    process.begin_owner_service_wait(operation, wait)
                } else {
                    process.begin_service(operation, fault_sequence)
                }
            } else {
                Err(super::native_process_runtime::NativeProcessError::Quarantined)
            };
            let result = process.settle_service_exit(result, exit);
            (result, process.native_service_phase())
        },
    )
    // Keep entry admission separate from dispatch/settlement: these source
    // locations and the exact error survive the existing fatal transport.
    .unwrap_or_else(|error| invalid_completion(native_service_invariant(error)));
    let result = native_service_completion(result, phase)
        .unwrap_or_else(|reason| invalid_completion(reason));
    Some(match result {
        NativeResume::Left(None) => native_service_idle(zone, slot, &mut sched::HardwareCpu),
        result => native_service_user_return(frame, operation, result, arm_signal_user_return),
    })
}

/// Publish an in-ring service completion before the final selected-owner
/// checkpoint. A parked service has no user-return boundary here.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
pub(super) fn native_service_user_return(
    frame: &mut TrapFrame,
    operation: Option<carrick_core_abi::service::ServiceOperation>,
    result: super::native_process_runtime::NativeResume,
    checkpoint: impl FnOnce(&mut TrapFrame) -> Action,
) -> Action {
    use super::native_process_runtime::NativeResume;
    match result {
        NativeResume::NoPending => checkpoint(frame),
        NativeResume::Returned(result) => {
            // Only an interrupted, uncommitted crossing may request restart.
            // Reuse the authenticated ARM return marker: FAR retains original
            // arg0 while the result word carries EINTR into shared policy.
            if result.raw() == carrick_syscall_abi::LINUX_EINTR.guest_retval()
                && matches!(operation,
                    Some(carrick_core_abi::service::ServiceOperation::Crossing { ordinal })
                    if ordinal.raw() == frame.x[8]
                        && carrick_signal_core::is_native_restartable_syscall(ordinal.raw()))
            {
                frame.far = frame.x[0];
                frame.esr = 0xfffe;
            }
            frame.x[0] = result.raw() as u64;
            checkpoint(frame)
        }
        _ => invalid_completion(NativeInvariant::EntryBinding),
    }
}

/// Finish the native service park before handing the executor to the host.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn native_service_idle(
    zone: &ZoneTables,
    slot: SlotId,
    cpu: &mut impl sched::ThreadCpu,
) -> Action {
    // The entry's seal vacates again (a no-op on a vacant word); leaving
    // here keeps the park's own order: the root first, then the word.
    let _vacated = sched::leave_space(zone, slot, cpu);
    Action::Idle
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn arm_deliver_declined_fault_signal_with<
    X: super::aarch64_process::ForkStockCrossing,
    F,
>(
    source: carrick_el1_abi::BornInZoneSource<'static, carrick_el1_abi::Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    page: &'static carrick_el1_abi::ThreadLifecyclePage,
    control: &'static carrick_el1_abi::ThreadControlSlot,
    service: &mut super::aarch64_process::Aarch64NativeProcessService<'static, X>,
    frame: &mut carrick_el1_abi::TrapFrame,
    owner_wait: &mut Option<carrick_el1_abi::PortalOwnerWait>,
    deliver: F,
) -> Result<carrick_el1_abi::Action, super::native_process_runtime::NativeProcessError>
where
    F: FnOnce(
        &mut super::native_process_runtime::NativeProcessEntry<
            '_,
            'static,
            super::aarch64_process::Mm,
            carrick_el1_abi::Aarch64ParkedContext,
            super::aarch64_process::Aarch64NativeProcessService<'static, X>,
        >,
        &mut TrapFrame,
    ) -> Option<carrick_personality_linux::dispatch::CompletionRoute>,
{
    if control.synchronous_fault().is_some() && !classified_fault_entry_permitted(frame.esr) {
        return Err(super::native_process_runtime::NativeProcessError::Invalid);
    }
    if carrick_el1::substrate::sched::NativeEntryVenue::select_with_lifecycle(
        source.zone,
        source.slot,
        task,
        page,
        control,
    ) != carrick_el1::substrate::sched::NativeEntryVenue::SignalOwner
    {
        // A sibling's exec/exit may have closed admission after publication.
        // Return a terminal fallback through the host's existing core/exit path;
        // retaining an awaiting-owner payload here would re-enter forever.
        if !carrick_el1_abi::Lifecycle::gate(page).serves_ring()
            && control.synchronous_fault().is_some()
        {
            control.synchronous_fault_default();
        }
        return Ok(Action::Forward);
    }
    // A host-classified fault returns through the durable signal checkpoint.
    // It is a fault return, never fatal-owner cancellation or syscall restart.
    let entry_syndrome = (frame.esr, frame.far);
    if let Some((_, _, address, _)) = control.synchronous_fault() {
        frame.esr = HOST_CLASSIFIED_DATA_ABORT_ESR;
        frame.far = address;
    }
    let action = declined_fault_admission_result(
        super::aarch64_process::deliver_declined_fault_signal_with(
            source,
            task,
            native,
            ttbr0,
            page,
            control,
            service,
            frame.far,
            |process| deliver(process, frame),
        ),
        owner_wait,
    )?;
    // Admission can also close between venue selection and the owner retain.
    if action == Action::Forward
        && !carrick_el1_abi::Lifecycle::gate(page).serves_ring()
        && control.synchronous_fault().is_some()
    {
        control.synchronous_fault_default();
        // The terminal verdict supersedes the owner dependency: nothing will
        // rerun this fault in ring, so no receipt may park the thread.
        *owner_wait = None;
    }
    if owner_wait.is_some() {
        // Nothing was delivered. The parked thread resumes at the faulting
        // instruction, so the entry syndrome must survive for that rerun.
        (frame.esr, frame.far) = entry_syndrome;
    }
    Ok(action)
}

/// Admission refusals precede signal publication; the loaded host executor
/// retains the fault on Forward. Only a broken binding is a carrier invariant.
/// An owner-memory wait is contention with a release notification: it keeps
/// the retained fault and hands the receipt to the caller, which parks the
/// thread on the owner and reruns the fault, exactly as a supply wait does.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) fn declined_fault_admission_result(
    result: Result<Action, super::native_process_runtime::NativeProcessError>,
    owner_wait: &mut Option<carrick_el1_abi::PortalOwnerWait>,
) -> Result<Action, super::native_process_runtime::NativeProcessError> {
    use super::native_process_runtime::NativeProcessError;
    match result {
        Ok(action) => Ok(action),
        Err(NativeProcessError::OwnerWait(wait)) => {
            *owner_wait = Some(wait);
            Ok(Action::Forward)
        }
        Err(
            error @ (NativeProcessError::Invalid
            | NativeProcessError::Stale
            | NativeProcessError::Quarantined),
        ) => Err(error),
        Err(
            NativeProcessError::Busy
            | NativeProcessError::Exhausted
            | NativeProcessError::Fault
            | NativeProcessError::ForkRefused(_)
            | NativeProcessError::Unsupported
            | NativeProcessError::GroupExitCustody
            | NativeProcessError::NoChild,
        ) => Ok(Action::Forward),
    }
}

#[cfg(test)]
#[test]
fn declined_fault_admission_busy_once_then_success() {
    use super::native_process_runtime::NativeProcessError;
    for error in [
        NativeProcessError::Busy,
        NativeProcessError::Exhausted,
        NativeProcessError::Fault,
        NativeProcessError::Unsupported,
        NativeProcessError::GroupExitCustody,
        NativeProcessError::NoChild,
    ] {
        let mut owner_wait = None;
        assert_eq!(
            declined_fault_admission_result(Err(error), &mut owner_wait),
            Ok(Action::Forward)
        );
        assert_eq!(owner_wait, None);
    }
    for error in [
        NativeProcessError::Invalid,
        NativeProcessError::Stale,
        NativeProcessError::Quarantined,
    ] {
        assert_eq!(
            declined_fault_admission_result(Err(error), &mut None),
            Err(error)
        );
    }
    assert_eq!(
        declined_fault_admission_result(Ok(Action::Served), &mut None),
        Ok(Action::Served)
    );
}

/// Production fault entry after ISA register capture and lifecycle address
/// binding. Admission composition is shared with the VM-free witnesses.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn arm_deliver_declined_fault_signal<X: super::aarch64_process::ForkStockCrossing, F>(
    source: carrick_el1_abi::BornInZoneSource<'static, carrick_el1_abi::Aarch64ParkedContext>,
    task: &'static CurrentTask,
    native: &carrick_sched_core::ThreadCtx,
    ttbr0: u64,
    page: &'static carrick_el1_abi::ThreadLifecyclePage,
    control: &'static carrick_el1_abi::ThreadControlSlot,
    service: &mut super::aarch64_process::Aarch64NativeProcessService<'static, X>,
    frame: &mut carrick_el1_abi::TrapFrame,
    owner_wait: &mut Option<carrick_el1_abi::PortalOwnerWait>,
    deliver: F,
) -> Result<carrick_el1_abi::Action, super::native_process_runtime::NativeProcessError>
where
    F: FnOnce(
        &mut super::native_process_runtime::NativeProcessEntry<
            '_,
            'static,
            super::aarch64_process::Mm,
            carrick_el1_abi::Aarch64ParkedContext,
            super::aarch64_process::Aarch64NativeProcessService<'static, X>,
        >,
        &mut TrapFrame,
    ) -> Option<carrick_personality_linux::dispatch::CompletionRoute>,
{
    arm_deliver_declined_fault_signal_with(
        source, task, native, ttbr0, page, control, service, frame, owner_wait, deliver,
    )
}

/// The in-ring synchronous fault venue for declined reservation permissions
/// and host-classified faults on a `SignalOwner` thread.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
pub(crate) fn arm_deliver_declined_fault_signal_current(
    frame: &mut TrapFrame,
    owner_wait: &mut Option<carrick_el1_abi::PortalOwnerWait>,
) -> Action {
    let current_tasks: &'static [CurrentTask; EL1_STACK_SLOTS as usize] =
        unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return Action::Forward;
    };
    let Some((page, control)) = task.lifecycle_refs() else {
        return Action::Forward;
    };
    let Some(slot) = SlotId::from_index(frame.slot as usize) else {
        return Action::Forward;
    };
    let zone: &'static ZoneTables = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
    let mut saved = alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    sched::ThreadCpu::save(
        &mut sched::HardwareCpu,
        frame,
        &mut saved,
        sched::CpuExitCause::Svc,
    );
    let ttbr0 = carrick_el1::isa::aarch64::hardware_live_ttbr();
    let mut service = super::aarch64_process::Aarch64NativeProcessService::new(task, slot)
        .unwrap_or_else(|_| invalid_completion(NativeInvariant::EntryBinding));
    arm_deliver_declined_fault_signal(
        carrick_el1_abi::BornInZoneSource { zone, slot },
        task,
        &saved.native,
        ttbr0,
        page,
        control,
        &mut service,
        frame,
        owner_wait,
        |process, frame| super::arm_signal::deliver_on_user_return(task, process, frame),
    )
    .unwrap_or_else(|_| invalid_completion(NativeInvariant::EntryBinding))
}

/// Lower-EL data abort, translation fault at level 0, used only to carry the
/// host-classified fault into the shared signal-frame builder.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
const HOST_CLASSIFIED_DATA_ABORT_ESR: u64 = 0x9200_0004;

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn classified_fault_entry_permitted(esr: u64) -> bool {
    // NativeOwnerCancel is the explicit host-to-owner fault checkpoint.
    esr == 0xfffc || matches!((esr >> 26) & 0x3f, 0x20 | 0x24)
}

/// The one native signal checkpoint at the actual EL0 return boundary. The
/// syscall work ledger and scheduler resume result have already settled here;
/// IRQ, fault and SVC returns all pass through the same owner.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
fn arm_signal_user_return(frame: &mut TrapFrame) -> Action {
    let current_tasks: &'static [CurrentTask; EL1_STACK_SLOTS as usize] =
        unsafe { &*(EL1_CURRENT_TASKS_BASE as *const [CurrentTask; EL1_STACK_SLOTS as usize]) };
    if current_tasks
        .get(frame.slot as usize)
        .and_then(|task| task.lifecycle_refs())
        .is_some_and(|(_, control)| control.synchronous_fault().is_some())
    {
        // A retained fault on a syscall/IRQ return is a broken entry binding.
        // Reject before the declined-fault prefix can rewrite the syndrome or
        // consume the syscall's unbudgeted service-exit stack envelope.
        if !classified_fault_entry_permitted(frame.esr) {
            invalid_completion(NativeInvariant::EntryBinding);
        }
        // This checkpoint has no fault rerun venue to park: an owner wait
        // stays Forward with the host-retained payload, as Busy does (#1083).
        return arm_deliver_declined_fault_signal_current(frame, &mut None);
    }
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
    let Some(slot) = SlotId::from_index(frame.slot as usize) else {
        invalid_completion(NativeInvariant::EntryBinding)
    };
    let zone: &'static ZoneTables = unsafe { &*(EL1_ZONE_BASE as *const ZoneTables) };
    let venue = carrick_el1::substrate::sched::NativeEntryVenue::select_with_lifecycle(
        zone, slot, task, page, control,
    );
    // Fatal cancellation drains an already owned wait after admission closes.
    // It does not admit new SignalOwner execution through a closed gate.
    if venue == carrick_el1::substrate::sched::NativeEntryVenue::Host
        && !(fatal_owner_cancel && control.native_signal_owner())
    {
        if fatal_owner_cancel {
            invalid_completion(NativeInvariant::EntryBinding)
        }
        return Action::Served;
    }
    if !fatal_owner_cancel && !carrick_el1_abi::Lifecycle::gate(page).serves_ring() {
        return Action::Served;
    }
    let source = carrick_el1_abi::BornInZoneSource { zone, slot };
    if frame.esr != 0xfffc
        && !(frame.esr == 0xfffe
            && frame.x[0] == carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64)
        && !control.has_in_zone_standard_signal()
        && carrick_el1::isa::signal_ingress_guest().is_empty()
        && control.zone_record().is_some_and(|record| {
            !super::aarch64_process::registry().signal_checkpoint_needed(zone, record)
        })
    {
        return Action::Served;
    }
    let mut saved = alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    sched::ThreadCpu::save(
        &mut sched::HardwareCpu,
        frame,
        &mut saved,
        sched::CpuExitCause::Svc,
    );
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
pub fn dispatch_syscall_with_lifecycle<'a, 'ipc, F, C, U, G>(
    frame: &'a mut G,
    counters: &'a Counters,
    current_tasks: &'a [CurrentTask],
    fd_map: &'a [FdMapSlot],
    object_table: &'a [DelegatedFile],
    open_table: &'a [DelegatedOpenFile],
    inotify_table: &'a [DelegatedInotify],
    name_cache: &'a InotifyNameCache,
    zone: Option<Zone<'a, C, U>>,
    ipc: Option<&'a ipc::IpcVenue<'ipc>>,
    lifecycle: Option<&'a dyn lifecycle::LifecycleVenue>,
    process: Option<&'a mut dyn lifecycle::ProcessNative<'ipc, LegacyDispatchContext>>,
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
        carrick_personality_linux::dispatch::CompletionRoute::NativeService => Action::Forward,
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
pub fn dispatch_syscall_with_native<'a, 'ipc, F, C, U, G, Context>(
    frame: &'a mut G,
    counters: &'a Counters,
    current_tasks: &'a [CurrentTask],
    fd_map: &'a [FdMapSlot],
    object_table: &'a [DelegatedFile],
    open_table: &'a [DelegatedOpenFile],
    inotify_table: &'a [DelegatedInotify],
    name_cache: &'a InotifyNameCache,
    zone: Option<Zone<'a, C, U>>,
    ipc: Option<&'a ipc::IpcVenue<'ipc>>,
    lifecycle: Option<&'a dyn lifecycle::LifecycleVenue>,
    process: Option<&'a mut dyn lifecycle::ProcessNative<'ipc, Context>>,
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

/// Closed set of physical custody failures at the native completion boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalCustodyInvariant {
    RootExitRefused,
    ForkCustodyRefused,
    AffinityTopologyMissing,
    InventoryRollbackFailed,
    NativeRunFailure(carrick_core_abi::NativeRunFailureReason),
}

impl PhysicalCustodyInvariant {
    /// Preserve the host fatal diagnostic text without using it as identity.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootExitRefused => "root exit crossing refused",
            Self::ForkCustodyRefused => "admitted fork custody commit refused",
            Self::AffinityTopologyMissing => {
                "affinity carrier topology missing after venue admission"
            }
            Self::InventoryRollbackFailed => "unexposed physical inventory rollback failed",
            Self::NativeRunFailure(reason) => reason.as_str(),
        }
    }
}

/// Native preparation, scheduling and completion retain an exact execution
/// binding. Missing frames and failed completion authentication share this
/// fail-stop transport; a completed effect must never be replayed by forwarding.
pub enum NativeInvariant {
    EntryBinding,
    NativeService(carrick_el1_abi::EntryBindingFatalReason),
    PhysicalCustody(PhysicalCustodyInvariant),
    MissingNativeFrame,
    RevisionCredit,
    SignalNumber,
    ProcessGraph(super::process_owner::GuestProcessInvariant),
    PipeOutput,
    /// [`NativeUnstagedExit::OwnedFamilyForward`]: an owned family's forward
    /// for a task with no host route.
    OwnedFamilyForward,
}

impl core::fmt::Debug for NativeInvariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EntryBinding => f.write_str("EntryBinding"),
            Self::PipeOutput => f.write_str("PipeOutput"),
            Self::OwnedFamilyForward => f.write_str("OwnedFamilyForward"),
            Self::NativeService(error) => f.debug_tuple("NativeService").field(error).finish(),
            Self::PhysicalCustody(reason) => f
                .debug_tuple("PhysicalCustody")
                .field(&reason.as_str())
                .finish(),
            Self::MissingNativeFrame => f.write_str("MissingNativeFrame"),
            Self::RevisionCredit => f.write_str("RevisionCredit"),
            Self::SignalNumber => f.write_str("SignalNumber"),
            Self::ProcessGraph(invariant) => {
                f.debug_tuple("ProcessGraph").field(invariant).finish()
            }
        }
    }
}

impl NativeInvariant {
    /// Target-independent mapping keeps fatal reason selection exhaustive and
    /// testable without entering the terminal transport.
    pub fn fatal_reason(&self) -> carrick_el1_abi::EntryBindingFatalReason {
        use carrick_el1_abi::EntryBindingFatalReason as Fatal;
        match self {
            NativeInvariant::EntryBinding => Fatal::EntryBinding,
            NativeInvariant::PipeOutput => Fatal::NativeServiceQuarantined,
            NativeInvariant::OwnedFamilyForward => Fatal::OwnedFamilyForward,
            NativeInvariant::NativeService(reason) => *reason,
            NativeInvariant::PhysicalCustody(reason) => match reason {
                PhysicalCustodyInvariant::RootExitRefused => Fatal::RootExitRefused,
                PhysicalCustodyInvariant::ForkCustodyRefused => Fatal::ForkCustodyRefused,
                PhysicalCustodyInvariant::AffinityTopologyMissing => Fatal::AffinityTopologyMissing,
                PhysicalCustodyInvariant::InventoryRollbackFailed
                | PhysicalCustodyInvariant::NativeRunFailure(_) => Fatal::PhysicalCustody,
            },
            NativeInvariant::MissingNativeFrame => Fatal::MissingNativeFrame,
            NativeInvariant::RevisionCredit => Fatal::RevisionCredit,
            NativeInvariant::SignalNumber => Fatal::SignalNumber,
            NativeInvariant::ProcessGraph(invariant) => {
                use super::process_owner::GuestProcessInvariant as Graph;
                use carrick_sched_core::process::registry::RegistryInvariant as Registry;
                match invariant {
                    Graph::NamespaceInternalIdentityOutOfRange(_) => Fatal::NamespaceIdentityRange,
                    Graph::NamespaceVisibleIdentityLost(_) => Fatal::NamespaceIdentityLost,
                    Graph::ExitCustodyLost(_) => Fatal::ExitCustodyLost,
                    Graph::ExitPublicationLost(_) => Fatal::ExitPublicationLost,
                    Graph::ExitReleaseLost(_) => Fatal::ExitReleaseLost,
                    Graph::Registry(invariant) => match invariant {
                        Registry::EpochExhausted => Fatal::RegistryEpochExhausted,
                        Registry::BirthPayloadMismatch => Fatal::BirthPayloadMismatch,
                        Registry::ProcessGroupCollision => Fatal::ProcessGroupCollision,
                        Registry::ProcessGroupIndexLost => Fatal::ProcessGroupIndexLost,
                        Registry::SessionCollision => Fatal::SessionCollision,
                        Registry::SessionIndexLost => Fatal::SessionIndexLost,
                        Registry::AutoreapAccountingLost => Fatal::AutoreapAccountingLost,
                    },
                }
            }
        }
    }
}

/// Encode before constructing the fatal envelope: an OwnerWait contains a
/// dependency, which must not enlarge every EL1 invariant's by-value frame.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn native_service_invariant(
    error: super::native_process_runtime::NativeProcessError,
) -> NativeInvariant {
    NativeInvariant::NativeService(native_service_fatal_reason(error))
}

/// The production service-exit failure boundary, also exercised by VM-free
/// native-process witnesses without invoking the non-returning fatal transport.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) fn native_service_completion(
    result: Result<
        super::native_process_runtime::NativeResume,
        super::native_process_runtime::NativeProcessError,
    >,
    phase: super::native_process_runtime::NativeServicePhase,
) -> Result<super::native_process_runtime::NativeResume, NativeInvariant> {
    result.map_err(|error| native_service_invariant_at(error, phase))
}

/// A stale dispatch identifies the last actual owner entered, rather than
/// implying that every stale refusal came from the service birth cell.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn native_service_invariant_at(
    error: super::native_process_runtime::NativeProcessError,
    phase: super::native_process_runtime::NativeServicePhase,
) -> NativeInvariant {
    use super::native_process_runtime::{NativeProcessError, NativeServicePhase as Phase};
    use carrick_el1_abi::EntryBindingFatalReason as Fatal;
    if !matches!(&error, NativeProcessError::Stale) {
        return native_service_invariant(error);
    }
    NativeInvariant::NativeService(match phase {
        Phase::Unspecified => Fatal::NativeServiceStale,
        Phase::Capability => Fatal::NativeServiceCapStale,
        Phase::Payload => Fatal::NativeServicePayloadStale,
        Phase::Member => Fatal::NativeServiceMemberStale,
        Phase::Birth => Fatal::NativeServiceBirthStale,
        Phase::Mm => Fatal::NativeServiceMmStale,
        Phase::Bind => Fatal::NativeServiceBindStale,
        Phase::Publication => Fatal::NativeServicePublishStale,
        Phase::Notice => Fatal::NativeServiceNoticeStale,
        Phase::Park => Fatal::NativeServiceParkStale,
        Phase::Completion => Fatal::NativeServiceCompleteStale,
        Phase::Settlement => Fatal::NativeServiceSettleStale,
    })
}

/// Preserve the refused operation's error without changing refusal policy.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
fn native_service_fatal_reason(
    error: super::native_process_runtime::NativeProcessError,
) -> carrick_el1_abi::EntryBindingFatalReason {
    use super::native_process_runtime::NativeProcessError as Error;
    use carrick_el1_abi::EntryBindingFatalReason as Fatal;
    match error {
        Error::Invalid => Fatal::NativeServiceInvalid,
        Error::Stale => Fatal::NativeServiceStale,
        Error::Exhausted => Fatal::NativeServiceExhausted,
        Error::Fault => Fatal::NativeServiceFault,
        Error::Unsupported => Fatal::NativeServiceUnsupported,
        Error::GroupExitCustody => Fatal::NativeServiceGroupExit,
        Error::Busy => Fatal::NativeServiceBusy,
        Error::Quarantined => Fatal::NativeServiceQuarantined,
        Error::NoChild => Fatal::NativeServiceNoChild,
        Error::OwnerWait(_) => Fatal::NativeServiceOwnerWait,
        Error::ForkRefused(refusal) => native_service_fatal_reason(refusal.error()),
    }
}

#[track_caller]
pub fn invalid_completion(reason: NativeInvariant) -> ! {
    #[cfg(target_os = "none")]
    carrick_el1::substrate::sched::hw::fatal_entry_binding(reason.fatal_reason());
    #[cfg(not(target_os = "none"))]
    carrick_fatal::carrick_fatal!(
        "el1::entry_completion",
        "native entry invariant: {reason:?}"
    )
}

fn complete_poll_copyout<'p, C: carrick_core_abi::EntryContext>(
    process: Option<&mut (dyn lifecycle::ProcessNative<'_, C> + 'p)>,
    task: &CurrentTask,
    address: carrick_guest_arch::UserVa,
    bytes: &[u8],
    result: SyscallResult,
) -> FamilyCompletion {
    if let Some(process) = process {
        return carrick_personality_linux::lifecycle::lifecycle_effect(&process.complete_copyout(
            address,
            bytes.to_vec(),
            result,
        ));
    }
    let mut copy = file::ValidatedCopy {
        task,
        validator: &file::HardwareValidator,
    };
    if copy.copy_out(address.raw(), bytes) {
        FamilyCompletion::Complete(result.raw())
    } else {
        // Host-owned legacy callers retain their existing owner-memory path.
        FamilyCompletion::Forward
    }
}

#[cfg(test)]
#[test]
fn host_owned_poll_copyout_refusal_keeps_the_host_fallback() {
    let task = CurrentTask::new();
    assert!(matches!(
        complete_poll_copyout::<carrick_sched_core::ThreadCtx>(
            None,
            &task,
            carrick_guest_arch::UserVa::new(carrick_guest_arch::USER_CEILING),
            &[0; 8],
            SyscallResult::new(1),
        ),
        FamilyCompletion::Forward
    ));
}

pub struct El1PendingFamilies<
    'a,
    'ipc,
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
    pub(super) ipc: Option<&'a ipc::IpcVenue<'ipc>>,
    pub(super) lifecycle: Option<&'a dyn lifecycle::LifecycleVenue>,
    pub(super) process: Option<&'a mut dyn lifecycle::ProcessNative<'ipc, Context>>,
    pub(super) source: Option<carrick_el1_abi::BornInZoneSource<'a, Context>>,
    pub(super) anonymous:
        Option<&'a mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue>,
    pub(super) cache_lookup: F,
}
impl<
    'a,
    'ipc,
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext,
> PendingFamilies<'a, Context> for El1PendingFamilies<'a, 'ipc, F, C, U, G, Context>
{
    fn resume_owned_continuation(&mut self) -> Option<lifecycle::LifecycleOutcome> {
        let process = self.process.as_deref_mut()?;
        let args = core::array::from_fn(|index| self.frame.argument(index).unwrap_or(0));
        if !carrick_personality_linux::sched::is_served_futex_op(
            self.frame.canonical_ordinal().raw(),
            args,
        ) {
            let _ = process.take_relative_futex_wait();
        }
        process.resume_owned_continuation()
    }
    fn may_serve_poll(&self) -> bool {
        self.frame.may_serve_poll()
    }
    fn native_descriptor_owner(&self) -> bool {
        matches!(
            self.native_descriptor_namespace(),
            NativeDescriptorNamespace::Native(_)
        )
    }
    fn may_serve_descriptor(&self) -> bool {
        let ordinal = self.frame.canonical_ordinal().raw();
        if self.native_descriptor_owner() {
            if [
                carrick_personality_linux::crossing::nr::PIPE2,
                carrick_personality_linux::crossing::nr::EVENTFD2,
                carrick_personality_linux::crossing::nr::EPOLL_CREATE1,
                carrick_personality_linux::crossing::nr::EPOLL_CTL,
                carrick_personality_linux::crossing::nr::DUP,
                carrick_personality_linux::crossing::nr::DUP3,
                carrick_personality_linux::crossing::nr::CLOSE,
            ]
            .iter()
            .any(|nr| nr.raw() == ordinal)
                || ordinal == carrick_syscall_abi::CARRICK_PRIVATE_X86_DUP2
            {
                return true;
            }
            if ordinal == carrick_personality_linux::crossing::nr::FCNTL.raw() {
                return matches!(
                    self.frame.argument(1).unwrap_or(u64::MAX),
                    carrick_abi::LINUX_F_DUPFD
                        | carrick_abi::LINUX_F_GETFD
                        | carrick_abi::LINUX_F_SETFD
                        | carrick_abi::LINUX_F_GETFL
                        | carrick_abi::LINUX_F_SETFL
                        | carrick_abi::LINUX_F_DUPFD_CLOEXEC
                );
            }
            return false;
        }
        if self.frame.may_serve_descriptor() {
            return ordinal != carrick_personality_linux::crossing::nr::FCNTL.raw();
        }
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
            .and_then(|process| {
                process.drain_owned_preparation();
                process.take_handoff_receipt()
            })
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
        if matches!(self.frame.canonical_ordinal().raw(), 122 | 123)
            && (self.process.is_none() || self.zone.as_ref()?.tables.carrier_cpu_count().is_none())
        {
            return None;
        }
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
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
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
            return match self
                .frame
                .query_host_readiness(&mut empty, timeout_ms, sig_mask)
            {
                Some(result) => FamilyCompletion::Complete(result),
                None if timeout_ms == 0 && matches!(sig_mask, PollSignalMask::Inherit) => {
                    FamilyCompletion::Complete(0)
                }
                None => FamilyCompletion::Forward,
            };
        }
        let file_table = task
            .linux
            .file_table
            .load(core::sync::atomic::Ordering::Acquire)
            .max(1);
        // Linux compares nfds with the caller's soft RLIMIT_NOFILE only after
        // the timespec and signal mask: EINVAL before the array is touched.
        let Some(limit) = super::file_table::poll_descriptor_limit(self.ipc, file_table) else {
            return FamilyCompletion::Forward;
        };
        if nfds > limit {
            return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        }
        // The guest sizes this array: a set the ring heap cannot hold is
        // ENOMEM (poll(2)), never an aborting allocation.
        let mut pollfds = alloc::vec::Vec::new();
        if pollfds.try_reserve_exact(nfds).is_err() {
            return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_ENOMEM.guest_retval());
        }
        pollfds.resize(nfds, super::file_table::PollFd::default());
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
        let host_entries = super::file_table::host_readiness_entries(
            self.fd_map,
            self.open_table,
            file_table,
            &pollfds,
            self.ipc,
        );
        let Ok(host_entries) = host_entries else {
            return FamilyCompletion::Complete(carrick_syscall_abi::LINUX_ENOMEM.guest_retval());
        };
        if let Some(mut entries) = host_entries {
            // The carrier samples the crossing with one host poll. A larger
            // host-bound set than it accepts is left unrouted before any
            // effect; the guest's nfds bound stays its soft RLIMIT_NOFILE.
            if entries.len() > super::file_table::HOST_READINESS_CROSSING_LIMIT {
                return FamilyCompletion::Forward;
            }
            let already_ready = super::file_table::resolve_poll_with_host_readiness(
                self.fd_map,
                self.open_table,
                self.object_table,
                self.ipc,
                file_table,
                &mut pollfds,
                Some(&entries),
            );
            let Some(already_ready) = already_ready else {
                return FamilyCompletion::Forward;
            };
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
                let Some(ready) = ready else {
                    return FamilyCompletion::Forward;
                };
                let out_bytes = unsafe {
                    core::slice::from_raw_parts(
                        pollfds.as_ptr() as *const u8,
                        nfds * core::mem::size_of::<super::file_table::PollFd>(),
                    )
                };
                let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
                    return FamilyCompletion::Forward;
                };
                return complete_poll_copyout(
                    self.process.as_deref_mut(),
                    task,
                    carrick_guest_arch::UserVa::new(fds_ptr),
                    out_bytes,
                    SyscallResult::new(ready as i64),
                );
            }
        }
        if !matches!(sig_mask, PollSignalMask::Inherit) {
            return FamilyCompletion::Forward;
        }
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return FamilyCompletion::Forward;
        };
        let ready = super::file_table::resolve_poll(
            self.fd_map,
            self.open_table,
            self.object_table,
            self.ipc,
            file_table,
            &mut pollfds,
        );
        let Some(ready) = ready else {
            return FamilyCompletion::Forward;
        };
        let out_bytes = unsafe {
            core::slice::from_raw_parts(
                pollfds.as_ptr() as *const u8,
                nfds * core::mem::size_of::<super::file_table::PollFd>(),
            )
        };
        if ready > 0 || timeout_ms == 0 {
            complete_poll_copyout(
                self.process.as_deref_mut(),
                task,
                carrick_guest_arch::UserVa::new(fds_ptr),
                out_bytes,
                SyscallResult::new(ready as i64),
            )
        } else {
            // This venue has no retained readiness wait. Leave the call
            // unrouted before output; clearing a slot and dropping a local
            // continuation cannot authorize a timeout result.
            FamilyCompletion::Forward
        }
    }
    fn descriptor(&mut self) -> FamilyCompletion {
        if self.native_descriptor_owner() {
            return self.serve_owned_ipc_descriptor();
        }
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
        // An owned descriptor call is different: its numeric and OFD effects
        // already committed in the ring. Inventing carrier work for that
        // completed call can only hand the same child straight back without a
        // producer changing state. Real descriptor host work still rings the
        // task doorbell and selects `WithWork` independently.
        let owned_descriptor = self.native_descriptor_owner() && self.may_serve_descriptor();
        self.frame.arm_frame_ref().is_some()
            && ((self.process.is_some() && !owned_descriptor)
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
    fn record_refusal(&self, bucket: usize) {
        self.counters.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(bucket as u64),
            if self
                .process
                .as_deref()
                .is_some_and(|process| !process.is_root_process())
            {
                carrick_core_abi::service::ServiceOrigin::Descendant
            } else {
                carrick_core_abi::service::ServiceOrigin::Initial
            },
            carrick_el1_abi::RefusalVenue::Ring,
        );
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
        let mut operation = self
            .process
            .as_deref_mut()
            .and_then(|process| process.take_relative_futex_wait());
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
            let served = sched.serve_futex_operation(frame, &mut operation);
            let disposition = match served {
                Ok(served) => served.map_or(ipc::IpcServed::Forward, ipc::IpcServed::from),
                Err(carrick_core::user_copy::CopyOutcome::Fault) => {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                    );
                }
                Err(carrick_core::user_copy::CopyOutcome::NotYet(request)) => {
                    let Some(process) = self.process.as_deref_mut() else {
                        return FamilyCompletion::Forward;
                    };
                    if let Some(operation) = operation {
                        process.retain_relative_futex_wait(operation);
                    }
                    let outcome = lifecycle::LifecycleNative::wait_guest_copy(self, request);
                    if !matches!(
                        outcome,
                        lifecycle::LifecycleOutcome::Redispatch
                            | lifecycle::LifecycleOutcome::Transferred { .. }
                    ) && let Some(process) = self.process.as_deref_mut()
                    {
                        let _ = process.take_relative_futex_wait();
                    }
                    return carrick_personality_linux::lifecycle::lifecycle_effect(&outcome);
                }
                Err(carrick_core::user_copy::CopyOutcome::Done) => {
                    invalid_completion(NativeInvariant::EntryBinding)
                }
            };
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
            // The stack guard witness (#369): never returns while the guard
            // below this CPU's EL1 stack is unmapped.
            2 => carrick_el1::alloc::run_stack_guard_witness(frame.x[1].min(64)),
            // The same overflow with a user-copy fixup armed must still fail
            // loud; a user pointer into a guard must be EFAULT (#369).
            3 => carrick_el1::alloc::run_armed_stack_guard_witness(cur_task, frame.x[1].min(64)),
            4 => carrick_el1::alloc::run_guard_user_pointer_witness(cur_task),
            5 => carrick_el1::alloc::run_armed_guard_store_witness(cur_task),
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
                        sched.park_object(&saved, key,
                            // SAFETY: the epoch was sampled before the mailbox
                            // state/generation probe above; park validates it.
                            unsafe { carrick_sched_core::object_wait::ObjectStateSnapshot::before_object_probe(snapshot) },
                            resume, operation, None)
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
    for El1PendingFamilies<'_, '_, F, C, U, G, Context>
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
        // A private file mmap the host-file venue already retained a byte
        // source for: this is its exact retry.
        let take = self
            .frame
            .arm_frame_ref()
            .filter(|frame| {
                frame.x[8] == carrick_personality_linux::native_host_file::LINUX_NR_MMAP.raw()
            })
            .map(|frame| {
                carrick_personality_linux::native_host_file::NativeMapKey::of(&[
                    frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
                ])
            })
            .and_then(|key| {
                self.process
                    .as_deref_mut()
                    .map(|process| process.take_map_source(key))
            })
            .unwrap_or_default();
        if !take.orphans.is_empty() {
            // Sources this thread was given but will not map go back to
            // the carrier through its MM's retirement stream.
            memory::retire_native_sources(
                task,
                access,
                memory::reservations::shared_guest(),
                slot.index() as u32,
                &take.orphans,
            );
        }
        let file = take.matched;
        match memory::serve_delegated_mapping(
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
            file,
        ) {
            memory::DelegatedAnonymous::PreparedConflict => DelegatedStep::PreparedConflict,
            memory::DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            memory::DelegatedAnonymous::Served => {
                DelegatedStep::Served(SyscallResult::new(self.frame.result().0 as i64))
            }
            // A private file mapping whose retained source the root still
            // would not take has no other venue: staging another source would
            // only repeat this answer. Counted ENOSYS, served in ring.
            memory::DelegatedAnonymous::Forward if file.is_some() => {
                let nr = carrick_personality_linux::native_host_file::LINUX_NR_MMAP.raw() as usize;
                <Self as PendingFamilies<'_, Context>>::record_refusal(self, nr);
                self.counters.served[nr].fetch_add(1, Ordering::Relaxed);
                DelegatedStep::Served(SyscallResult::new(
                    carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
                ))
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

// An unavailable publication cannot select the legacy numeric namespace.
enum NativeDescriptorNamespace {
    Legacy,
    Native(Option<carrick_el1_abi::ipc::RawTableId>),
}

struct NativeFdWait;
impl carrick_el1_abi::ipc::LockWait for NativeFdWait {
    fn wait(&self, _attempt: u32) -> bool {
        core::hint::spin_loop();
        true
    }
}

/// Constructor custody contains no published descriptor until copyout finishes.
/// The exact region, pins and numeric claims survive an owner-memory park.
struct PipeOutput<'a> {
    region: carrick_el1_abi::ipc::IpcRegion<'a>,
    claims: Option<carrick_fd_core::reservation::PairReservation>,
    pins: [Option<carrick_el1_abi::ipc::OfdPin>; 2],
    backings: [Option<carrick_el1_abi::ipc::BackingToken>; 2],
    cloexec: bool,
}
impl lifecycle::CopyoutEffect for PipeOutput<'_> {
    fn commit(&mut self) -> Result<(), carrick_syscall_abi::LinuxErrno> {
        let authority = self.region.fd(NativeFdWait);
        let claims = self.claims.as_mut().ok_or(carrick_syscall_abi::LINUX_EIO)?;
        authority
            .publish_pair(claims, &mut self.pins, self.cloexec)
            .map_err(|_| carrick_syscall_abi::LINUX_EIO)?;
        self.claims = None;
        Ok(())
    }
}
impl Drop for PipeOutput<'_> {
    fn drop(&mut self) {
        let authority = self.region.fd(NativeFdWait);
        if let Some(mut claims) = self.claims.take() {
            match authority.cancel_pair(&mut claims) {
                Ok(()) | Err(carrick_fd_core::Error::StaleTable) => {}
                Err(_) => invalid_completion(NativeInvariant::PipeOutput),
            }
        }
        for (pin, backing) in self.pins.iter_mut().zip(self.backings.iter_mut()) {
            let release = if let Some(pin) = pin.take() {
                authority
                    .unpin(pin)
                    .unwrap_or_else(|_| invalid_completion(NativeInvariant::PipeOutput))
                    .map(|description| description.backing)
            } else {
                backing.take()
            };
            if let Some(backing) = release {
                self.region
                    .release_backing(backing, &NativeFdWait)
                    .unwrap_or_else(|_| invalid_completion(NativeInvariant::PipeOutput));
            }
        }
    }
}

#[derive(Clone, Copy)]
enum NativeDupTarget {
    Lowest(carrick_el1_abi::ipc::fd::Fd),
    FcntlMin(carrick_el1_abi::ipc::fd::Fd),
    Exact(carrick_el1_abi::ipc::fd::Fd),
}

#[derive(Clone, Copy)]
struct NativeDupRequest {
    old: carrick_el1_abi::ipc::fd::Fd,
    target: NativeDupTarget,
    cloexec: bool,
}

#[inline(never)]
fn raise_native_sigpipe<'p, Context: DispatchContext>(
    process: Option<&mut (dyn lifecycle::ProcessNative<'_, Context> + 'p)>,
) {
    if let Some(signals) = process.and_then(|p| p.signal_venue()) {
        signals.raise_sigpipe();
    }
}

fn map_fd_error(error: carrick_el1_abi::ipc::fd::Error) -> FamilyCompletion {
    use carrick_el1_abi::ipc::fd::Error;
    let errno = match error {
        Error::BadFd => carrick_syscall_abi::LINUX_EBADF,
        Error::InvalidArgument => carrick_syscall_abi::LINUX_EINVAL,
        Error::TooManyFiles => carrick_syscall_abi::LINUX_EMFILE,
        Error::NoMemory | Error::NeedsBacking { .. } | Error::NeedsOfds => {
            carrick_syscall_abi::LINUX_ENOMEM
        }
        Error::Busy => carrick_abi::LINUX_EBUSY,
        Error::Contended
        | Error::StaleTable
        | Error::BadBacking
        | Error::StalePin
        | Error::PinRaced(_) => carrick_syscall_abi::LINUX_EIO,
    };
    FamilyCompletion::Complete(errno.guest_retval())
}

fn map_ipc_error(error: carrick_el1_abi::ipc::IpcError) -> FamilyCompletion {
    match error {
        carrick_el1_abi::ipc::IpcError::ZoneLimit => {
            FamilyCompletion::Complete(carrick_abi::LINUX_ENFILE.guest_retval())
        }
        carrick_el1_abi::ipc::IpcError::Fd(fd_err) => map_fd_error(fd_err),
        _ => FamilyCompletion::Complete(carrick_syscall_abi::LINUX_EIO.guest_retval()),
    }
}

fn run_with_table_growth<T>(
    region: &carrick_el1_abi::ipc::IpcRegion<'_>,
    table: carrick_el1_abi::ipc::fd::TableId,
    mut op: impl FnMut(
        carrick_el1_abi::ipc::IpcFdAuthority<'_, NativeFdWait>,
    ) -> Result<T, carrick_el1_abi::ipc::fd::Error>,
) -> Result<T, FamilyCompletion> {
    loop {
        let seen = region.ofd_count();
        match op(region.fd(NativeFdWait)) {
            Ok(val) => return Ok(val),
            Err(carrick_el1_abi::ipc::fd::Error::NeedsBacking { descriptors }) => {
                region
                    .ensure_table_capacity(table, descriptors, &NativeFdWait)
                    .map_err(map_ipc_error)?;
            }
            Err(carrick_el1_abi::ipc::fd::Error::NeedsOfds) => {
                region.grow_ofds(seen).map_err(map_ipc_error)?;
            }
            Err(err) => return Err(map_fd_error(err)),
        }
    }
}

impl<F, C: sched::ThreadCpu, U: sched::UserWord, G: GuestDispatchFrame, Context: DispatchContext>
    El1PendingFamilies<'_, '_, F, C, U, G, Context>
{
    fn native_descriptor_namespace(&self) -> NativeDescriptorNamespace {
        let native = self
            .process
            .as_deref()
            .is_some_and(|process| process.owns_descriptor_namespace());
        let Some((venue, task)) = self.ipc.zip(self.task()) else {
            return if native {
                NativeDescriptorNamespace::Native(None)
            } else {
                NativeDescriptorNamespace::Legacy
            };
        };
        if let Some(table) = venue.tables.owned_table_of(task) {
            return NativeDescriptorNamespace::Native(Some(table));
        }
        if native {
            return NativeDescriptorNamespace::Native(venue.tables.table_of(task));
        }
        // A borrowed root table can also own ring-created objects. Keep
        // native tasks' missing-table authority above, while selecting the
        // same constructor and zone-description owner for the live root.
        let table = venue.tables.table_of(task);
        let ordinal = self.frame.canonical_ordinal();
        let constructor = matches!(
            ordinal,
            carrick_personality_linux::crossing::nr::PIPE2
                | carrick_personality_linux::crossing::nr::EVENTFD2
                | carrick_personality_linux::crossing::nr::EPOLL_CREATE1
                | carrick_personality_linux::crossing::nr::EPOLL_CTL
        );
        let zone_description = table.is_some_and(|raw| {
            venue
                .region
                .fd(NativeFdWait)
                .get(
                    carrick_el1_abi::ipc::fd::TableId::from_raw(raw),
                    carrick_el1_abi::ipc::fd::Fd(self.frame.argument(0).unwrap_or(0) as i32),
                )
                .is_ok_and(ipc::is_zone_releasable_backing)
        });
        if constructor || zone_description {
            return NativeDescriptorNamespace::Native(table);
        }
        NativeDescriptorNamespace::Legacy
    }

    fn settle_delegated_release(
        frame: &mut G,
        open_table: &[DelegatedOpenFile],
        task: &CurrentTask,
        release: Option<super::file_table::ReleasedDescription>,
    ) -> Result<(), FamilyCompletion> {
        let Some(release) = release else {
            return Ok(());
        };
        task.linux.mark_pending_host_work();
        let binding = open_table
            .get(release.handle.checked_sub(1).unwrap_or(u32::MAX) as usize)
            .and_then(DelegatedOpenFile::host_object);
        if binding.is_some_and(|b| b.stdio_fd().is_some())
            && !binding
                .is_some_and(|b| frame.release_host_object(b, release.handle, release.incarnation))
        {
            return Err(FamilyCompletion::Complete(
                carrick_syscall_abi::LINUX_EIO.guest_retval(),
            ));
        }
        Ok(())
    }

    fn duplicate_owned_ipc(
        &mut self,
        venue: &ipc::IpcVenue<'_>,
        task: &CurrentTask,
        table: carrick_el1_abi::ipc::fd::TableId,
        file_table: u64,
        request: NativeDupRequest,
        zone: Option<(&ZoneTables, SlotId)>,
    ) -> Result<carrick_el1_abi::ipc::fd::Fd, FamilyCompletion> {
        use super::file_table::HostBindingDupError;
        use carrick_el1_abi::ipc::fd::Error;

        let authority = venue.region.fd(NativeFdWait);
        let (pin, _) = authority.pin(table, request.old).map_err(map_fd_error)?;
        let reservation =
            match run_with_table_growth(&venue.region, table, |auth| match request.target {
                NativeDupTarget::Lowest(min) => auth.reserve_min(table, min),
                NativeDupTarget::FcntlMin(min) => auth.reserve_dup_min(table, min),
                NativeDupTarget::Exact(fd) => auth.reserve_exact(table, fd),
            }) {
                Ok(reservation) => reservation,
                Err(error) => {
                    let release = authority
                        .unpin_filtered(pin, ipc::is_zone_releasable_backing)
                        .map_err(map_fd_error)?;
                    ipc::settle_native_release(&venue.region, release, zone, task)
                        .map_err(map_ipc_error)?;
                    return Err(error);
                }
            };
        let new_fd = reservation.fd();
        let mut reservation = Some(reservation);
        let projected = super::file_table::with_host_binding_dup(
            self.fd_map,
            self.open_table,
            file_table,
            request.old.0,
            new_fd.0,
            request.cloexec,
            || {
                let claim = reservation.take().ok_or(Error::InvalidArgument)?;
                match authority.commit_reservation_filtered(
                    claim,
                    &pin,
                    request.cloexec,
                    ipc::is_zone_releasable_backing,
                ) {
                    Ok(release) => Ok(release),
                    Err(refused) => {
                        let error = refused.error();
                        reservation = Some(refused.into_reservation());
                        Err(error)
                    }
                }
            },
        );

        let projected = match projected {
            Ok(projected) => Ok(projected),
            Err(HostBindingDupError::Full) => Err(map_fd_error(Error::TooManyFiles)),
            Err(HostBindingDupError::Invalid) => Err(map_fd_error(Error::BadBacking)),
            Err(HostBindingDupError::Mutation(error)) => Err(map_fd_error(error)),
        };
        if let Some(claim) = reservation {
            authority
                .cancel_reservation(claim)
                .map_err(|refused| map_fd_error(refused.error()))?;
        }
        let pin_release = authority
            .unpin_filtered(pin, ipc::is_zone_releasable_backing)
            .map_err(map_fd_error)?;
        ipc::settle_native_release(&venue.region, pin_release, zone, task)
            .map_err(map_ipc_error)?;

        let (release, delegated_release) = projected?;
        ipc::settle_native_release(&venue.region, release, zone, task).map_err(map_ipc_error)?;
        Self::settle_delegated_release(self.frame, self.open_table, task, delegated_release)?;
        Ok(new_fd)
    }

    #[inline(never)]
    fn serve_owned_ipc_descriptor(&mut self) -> FamilyCompletion {
        use carrick_el1_abi::ipc::fd::{AccessMode, Fd, TableId};
        let Some(venue) = self.ipc else {
            return FamilyCompletion::Forward;
        };
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return FamilyCompletion::Forward;
        };
        let NativeDescriptorNamespace::Native(Some(raw)) = self.native_descriptor_namespace()
        else {
            return FamilyCompletion::Forward;
        };
        let table = TableId::from_raw(raw);
        let file_table = task.linux.file_table.load(Ordering::Acquire).max(1);
        let ordinal = self.frame.canonical_ordinal().raw();
        let old = Fd(self.frame.argument(0).unwrap_or(0) as i32);
        let zone = self
            .zone
            .as_ref()
            .zip(self.frame.slot())
            .map(|(z, slot)| (z.tables, slot));

        match ordinal {
            nr if nr == carrick_personality_linux::crossing::nr::PIPE2.raw() => {
                use carrick_el1_abi::ipc::{
                    IpcBacking,
                    fd::{Description, StatusFlags},
                    pipe::End,
                };
                let flags = self.frame.argument(1).unwrap_or(0) as u32 as u64;
                if flags & !(carrick_syscall_abi::LINUX_O_CLOEXEC | carrick_abi::LINUX_O_NONBLOCK)
                    != 0
                {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                    );
                }
                let Some(process) = self.process.as_deref_mut() else {
                    return FamilyCompletion::Forward;
                };
                let mut claims = match run_with_table_growth(&venue.region, table, |auth| {
                    auth.reserve_pair(table)
                }) {
                    Ok(claims) => claims,
                    Err(error) => return error,
                };
                let object = loop {
                    let seen = venue.region.object_count();
                    match venue.region.create_pipe(65536, &NativeFdWait) {
                        Ok(object) => break object,
                        Err(carrick_el1_abi::ipc::IpcError::NoObjects) => {
                            if let Err(error) = venue.region.grow_objects(seen) {
                                let _ = venue.region.fd(NativeFdWait).cancel_pair(&mut claims);
                                return map_ipc_error(error);
                            }
                        }
                        Err(error) => {
                            let _ = venue.region.fd(NativeFdWait).cancel_pair(&mut claims);
                            return map_ipc_error(error);
                        }
                    }
                };
                let Some(fds) = claims.fds() else {
                    invalid_completion(NativeInvariant::PipeOutput)
                };
                let backings = [End::Reader, End::Writer]
                    .map(|end| Some(IpcBacking::Pipe { object, end }.encode()));
                let mut output = PipeOutput {
                    region: venue.region,
                    claims: Some(claims),
                    pins: [None, None],
                    backings,
                    cloexec: flags & carrick_syscall_abi::LINUX_O_CLOEXEC != 0,
                };
                if let Some((zone, _)) = zone {
                    for lane in [
                        carrick_el1_abi::ipc::pipe::WaitFor::Readable,
                        carrick_el1_abi::ipc::pipe::WaitFor::Writable,
                    ] {
                        if let Some(key) = carrick_el1_abi::ipc::object_wait_key(object, lane)
                            && zone
                                .bind_object_wait(
                                    key,
                                    &carrick_sched_core::ShortLockSpin,
                                    &|owned| {
                                        crate::sched::object_wait::deliver_host_completion(
                                            owned.zone(),
                                            owned,
                                        )
                                    },
                                )
                                .is_err()
                        {
                            return FamilyCompletion::Complete(
                                carrick_syscall_abi::LINUX_EIO.guest_retval(),
                            );
                        }
                    }
                }
                for (index, access) in [AccessMode::ReadOnly, AccessMode::WriteOnly]
                    .into_iter()
                    .enumerate()
                {
                    let Some(backing) = output.backings[index] else {
                        invalid_completion(NativeInvariant::PipeOutput)
                    };
                    let description = Description::new(
                        backing,
                        access,
                        StatusFlags {
                            nonblock: flags & carrick_abi::LINUX_O_NONBLOCK != 0,
                            ..StatusFlags::default()
                        },
                    );
                    match run_with_table_growth(&venue.region, table, |auth| {
                        auth.create_pinned(description)
                    }) {
                        Ok(pin) => {
                            output.pins[index] = Some(pin);
                            output.backings[index] = None;
                        }
                        Err(error) => return error,
                    }
                }
                let bytes = fds.into_iter().flat_map(|fd| fd.0.to_ne_bytes()).collect();
                lifecycle::lifecycle_effect(&process.complete_constructor_output(
                    carrick_guest_arch::UserVa::new(self.frame.argument(0).unwrap_or(0)),
                    bytes,
                    alloc::boxed::Box::new(output),
                ))
            }
            nr if nr == carrick_personality_linux::crossing::nr::EPOLL_CREATE1.raw()
                || nr == carrick_personality_linux::crossing::nr::EVENTFD2.raw() =>
            {
                use carrick_el1_abi::ipc::{EventMode, IpcBacking};
                let eventfd = nr == carrick_personality_linux::crossing::nr::EVENTFD2.raw();
                let flags = self.frame.argument(usize::from(eventfd)).unwrap_or(0) as u32 as u64;
                let allowed = carrick_syscall_abi::LINUX_O_CLOEXEC
                    | if eventfd {
                        carrick_abi::LINUX_O_NONBLOCK | carrick_abi::LINUX_EFD_SEMAPHORE
                    } else {
                        0
                    };
                if flags & !allowed != 0 {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                    );
                }
                let object = loop {
                    let seen = venue.region.object_count();
                    let created = if eventfd {
                        let mode = if flags & carrick_abi::LINUX_EFD_SEMAPHORE != 0 {
                            EventMode::Semaphore
                        } else {
                            EventMode::Counter
                        };
                        venue.region.create_eventfd(
                            self.frame.argument(0).unwrap_or(0) as u32,
                            mode,
                            &NativeFdWait,
                        )
                    } else {
                        venue.region.create_epoll(&NativeFdWait)
                    };
                    match created {
                        Ok(object) => break object,
                        Err(carrick_el1_abi::ipc::IpcError::NoObjects) => {
                            if let Err(error) = venue.region.grow_objects(seen) {
                                return map_ipc_error(error);
                            }
                        }
                        Err(error) => return map_ipc_error(error),
                    }
                };
                let backing = if eventfd {
                    IpcBacking::EventFd { object }
                } else {
                    IpcBacking::Epoll { object }
                }
                .encode();
                if let Some((zone, _)) = zone {
                    for lane in [
                        carrick_el1_abi::ipc::pipe::WaitFor::Readable,
                        carrick_el1_abi::ipc::pipe::WaitFor::Writable,
                    ] {
                        if let Some(key) = carrick_el1_abi::ipc::object_wait_key(object, lane)
                            && zone
                                .bind_object_wait(
                                    key,
                                    &carrick_sched_core::ShortLockSpin,
                                    &|owned| {
                                        crate::sched::object_wait::deliver_host_completion(
                                            owned.zone(),
                                            owned,
                                        )
                                    },
                                )
                                .is_err()
                        {
                            if let Err(error) = venue.region.release_backing(backing, &NativeFdWait)
                            {
                                return map_ipc_error(error);
                            }
                            return FamilyCompletion::Complete(
                                carrick_syscall_abi::LINUX_EIO.guest_retval(),
                            );
                        }
                    }
                }
                let description = carrick_el1_abi::ipc::fd::Description::new(
                    backing,
                    AccessMode::ReadWrite,
                    carrick_el1_abi::ipc::fd::StatusFlags {
                        nonblock: eventfd && flags & carrick_abi::LINUX_O_NONBLOCK != 0,
                        ..Default::default()
                    },
                );
                let result = run_with_table_growth(&venue.region, table, |auth| {
                    auth.open(
                        table,
                        Fd(0),
                        description,
                        flags & carrick_syscall_abi::LINUX_O_CLOEXEC != 0,
                    )
                });
                match result {
                    Ok(fd) => FamilyCompletion::Complete(i64::from(fd.0)),
                    Err(error) => {
                        if let Err(release) = venue.region.release_backing(backing, &NativeFdWait) {
                            return map_ipc_error(release);
                        }
                        error
                    }
                }
            }
            nr if nr == carrick_personality_linux::crossing::nr::EPOLL_CTL.raw() => {
                use carrick_el1_abi::ipc::{
                    IpcBacking,
                    epoll::{EpollCtlError, EpollMember},
                };
                let authority = venue.region.fd(NativeFdWait);
                let (epin, edesc) = match authority.pin(table, old) {
                    Ok(pair) => pair,
                    Err(error) => return map_fd_error(error),
                };
                let result = (|| {
                    let Some(IpcBacking::Epoll { object: epoll }) =
                        IpcBacking::decode(edesc.backing)
                    else {
                        // Host epolls retain their existing service; this
                        // adapter owns only the shared zone representation.
                        return FamilyCompletion::Forward;
                    };
                    let member_fd = Fd(self.frame.argument(2).unwrap_or(0) as i32);
                    if member_fd == old {
                        return FamilyCompletion::Complete(
                            carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                        );
                    }
                    let (pin, description) = match authority.pin(table, member_fd) {
                        Ok(pair) => pair,
                        Err(error) => return map_fd_error(error),
                    };
                    let result = (|| {
                        let Some((member, kind)) = IpcBacking::decode(description.backing)
                            .and_then(EpollMember::of_backing)
                        else {
                            return FamilyCompletion::Forward;
                        };
                        let op = self.frame.argument(1).unwrap_or(0) as u32 as u64;
                        let mut bytes = [0u8; 16];
                        let data_offset = if self.frame.arm_scheduler() { 8 } else { 4 };
                        let event_bytes = data_offset + 8;
                        if op != carrick_abi::LINUX_EPOLL_CTL_DEL {
                            let mut user = file::ValidatedCopy {
                                task,
                                validator: &file::HardwareValidator,
                            };
                            if !user.copy_in(
                                &mut bytes[..event_bytes],
                                self.frame.argument(3).unwrap_or(0),
                            ) {
                                return FamilyCompletion::Complete(
                                    carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                                );
                            }
                        }
                        let events = u32::from_ne_bytes(bytes[..4].try_into().unwrap_or_default());
                        let data = u64::from_ne_bytes(
                            bytes[data_offset..event_bytes]
                                .try_into()
                                .unwrap_or_default(),
                        );
                        let key = pin.key();
                        let key =
                            (u64::from(key.index) << 32) | (key.generation & u64::from(u32::MAX));
                        let result = match op {
                            carrick_abi::LINUX_EPOLL_CTL_ADD => venue.region.epoll_add(
                                epoll,
                                member,
                                kind,
                                member_fd.0,
                                key,
                                events,
                                data,
                                &NativeFdWait,
                            ),
                            carrick_abi::LINUX_EPOLL_CTL_MOD => venue.region.epoll_modify(
                                epoll,
                                member_fd.0,
                                key,
                                events,
                                data,
                                &NativeFdWait,
                            ),
                            carrick_abi::LINUX_EPOLL_CTL_DEL => venue
                                .region
                                .epoll_delete(epoll, member_fd.0, key, &NativeFdWait)
                                .map(|()| None),
                            _ => {
                                return FamilyCompletion::Complete(
                                    carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                                );
                            }
                        };
                        match result {
                            Ok(wake) => {
                                if let Some(wake) = wake {
                                    ipc::notify_native_wake(wake, zone, task);
                                }
                                FamilyCompletion::Complete(0)
                            }
                            Err(EpollCtlError::Exists) => {
                                FamilyCompletion::Complete(carrick_abi::LINUX_EEXIST.guest_retval())
                            }
                            Err(EpollCtlError::NotFound) => {
                                FamilyCompletion::Complete(carrick_abi::LINUX_ENOENT.guest_retval())
                            }
                            Err(EpollCtlError::Invalid) => FamilyCompletion::Complete(
                                carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                            ),
                            Err(EpollCtlError::HostHalf(_)) => FamilyCompletion::Forward,
                            Err(EpollCtlError::Ipc(error)) => map_ipc_error(error),
                        }
                    })();
                    match authority.unpin_filtered(pin, ipc::is_zone_releasable_backing) {
                        Ok(release) => {
                            if let Err(error) =
                                ipc::settle_native_release(&venue.region, release, zone, task)
                            {
                                return map_ipc_error(error);
                            }
                        }
                        Err(error) => return map_fd_error(error),
                    }
                    result
                })();
                match authority.unpin_filtered(epin, ipc::is_zone_releasable_backing) {
                    Ok(release) => {
                        if let Err(error) =
                            ipc::settle_native_release(&venue.region, release, zone, task)
                        {
                            return map_ipc_error(error);
                        }
                    }
                    Err(error) => return map_fd_error(error),
                }
                result
            }
            nr if nr == carrick_personality_linux::crossing::nr::DUP.raw() => {
                let new_fd = match self.duplicate_owned_ipc(
                    venue,
                    task,
                    table,
                    file_table,
                    NativeDupRequest {
                        old,
                        target: NativeDupTarget::Lowest(Fd(0)),
                        cloexec: false,
                    },
                    zone,
                ) {
                    Ok(fd) => fd,
                    Err(done) => return done,
                };
                FamilyCompletion::Complete(i64::from(new_fd.0))
            }
            nr if nr == carrick_personality_linux::crossing::nr::DUP3.raw() => {
                let new = Fd(self.frame.argument(1).unwrap_or(0) as i32);
                let flags = self.frame.argument(2).unwrap_or(0);
                if flags & !carrick_syscall_abi::LINUX_O_CLOEXEC != 0 || old == new {
                    return FamilyCompletion::Complete(
                        carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                    );
                }
                let cloexec = flags != 0;
                let new_fd = match self.duplicate_owned_ipc(
                    venue,
                    task,
                    table,
                    file_table,
                    NativeDupRequest {
                        old,
                        target: NativeDupTarget::Exact(new),
                        cloexec,
                    },
                    zone,
                ) {
                    Ok(fd) => fd,
                    Err(done) => return done,
                };
                FamilyCompletion::Complete(i64::from(new_fd.0))
            }
            nr if nr == carrick_syscall_abi::CARRICK_PRIVATE_X86_DUP2 => {
                let new = Fd(self.frame.argument(1).unwrap_or(0) as i32);
                if old == new {
                    return match venue.region.fd(NativeFdWait).get(table, old) {
                        Ok(_) => FamilyCompletion::Complete(i64::from(new.0)),
                        Err(error) => map_fd_error(error),
                    };
                }
                match self.duplicate_owned_ipc(
                    venue,
                    task,
                    table,
                    file_table,
                    NativeDupRequest {
                        old,
                        target: NativeDupTarget::Exact(new),
                        cloexec: false,
                    },
                    zone,
                ) {
                    Ok(fd) => FamilyCompletion::Complete(i64::from(fd.0)),
                    Err(done) => done,
                }
            }
            nr if nr == carrick_personality_linux::crossing::nr::CLOSE.raw() => {
                let close_effects = match venue.region.fd(NativeFdWait).close_effects(table, old) {
                    Ok(effects) => effects,
                    Err(err) => return map_fd_error(err),
                };
                let released = match venue.region.fd(NativeFdWait).close_filtered(
                    table,
                    old,
                    ipc::is_zone_releasable_backing,
                ) {
                    Ok(rel) => rel,
                    Err(err) => return map_fd_error(err),
                };
                if let Err(err) = ipc::settle_native_release(&venue.region, released, zone, task) {
                    return map_ipc_error(err);
                }
                let change = super::file_table::close_host_binding(
                    self.fd_map,
                    self.open_table,
                    file_table,
                    old.0,
                );
                if let Err(err) = Self::settle_delegated_release(
                    self.frame,
                    self.open_table,
                    task,
                    change.and_then(|c| c.release),
                ) {
                    return err;
                }
                if close_effects.is_empty() {
                    FamilyCompletion::Complete(0)
                } else {
                    // The numeric fd is already gone from the one shared
                    // authority. Replay only the host-owned close effects:
                    // the host FileTable observes the shared BadFd as an
                    // idempotent projection and runs its canonical record-lock,
                    // epoll and inotify teardown exactly once.
                    FamilyCompletion::CommitOwed(0)
                }
            }
            nr if nr == carrick_personality_linux::crossing::nr::FCNTL.raw() => {
                let cmd = self.frame.argument(1).unwrap_or(u64::MAX);
                let arg = self.frame.argument(2).unwrap_or(0);
                match cmd {
                    carrick_abi::LINUX_F_DUPFD | carrick_abi::LINUX_F_DUPFD_CLOEXEC => {
                        let cloexec = cmd == carrick_abi::LINUX_F_DUPFD_CLOEXEC;
                        let Ok(min) = i32::try_from(arg) else {
                            return FamilyCompletion::Complete(
                                carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                            );
                        };
                        let min = Fd(min);
                        let new_fd = match self.duplicate_owned_ipc(
                            venue,
                            task,
                            table,
                            file_table,
                            NativeDupRequest {
                                old,
                                target: NativeDupTarget::FcntlMin(min),
                                cloexec,
                            },
                            zone,
                        ) {
                            Ok(fd) => fd,
                            Err(done) => return done,
                        };
                        FamilyCompletion::Complete(i64::from(new_fd.0))
                    }
                    carrick_abi::LINUX_F_GETFD => {
                        match venue.region.fd(NativeFdWait).getfd(table, old) {
                            Ok(cloexec) => FamilyCompletion::Complete(
                                i64::from(cloexec) * (carrick_abi::LINUX_FD_CLOEXEC as i64),
                            ),
                            Err(err) => map_fd_error(err),
                        }
                    }
                    carrick_abi::LINUX_F_SETFD => {
                        let cloexec = arg & carrick_abi::LINUX_FD_CLOEXEC != 0;
                        if let Err(err) = venue.region.fd(NativeFdWait).setfd(table, old, cloexec) {
                            return map_fd_error(err);
                        }
                        if let Some((_, index)) = fd_map_lookup(self.fd_map, file_table, old.0) {
                            if cloexec {
                                self.fd_map[index].fd_flags.fetch_or(
                                    super::file_table::GUEST_FD_CLOEXEC,
                                    Ordering::Release,
                                );
                            } else {
                                self.fd_map[index].fd_flags.fetch_and(
                                    !super::file_table::GUEST_FD_CLOEXEC,
                                    Ordering::Release,
                                );
                            }
                        }
                        FamilyCompletion::Complete(0)
                    }
                    carrick_abi::LINUX_F_GETFL => {
                        match venue.region.fd(NativeFdWait).getfl(table, old) {
                            Ok((access, flags)) => {
                                let acc = match access {
                                    AccessMode::ReadOnly => carrick_abi::LINUX_O_RDONLY,
                                    AccessMode::WriteOnly => carrick_abi::LINUX_O_WRONLY,
                                    AccessMode::ReadWrite => carrick_abi::LINUX_O_RDWR,
                                    AccessMode::Path => carrick_abi::LINUX_O_PATH,
                                };
                                let out = acc
                                    | (u64::from(flags.append) * carrick_abi::LINUX_O_APPEND)
                                    | (u64::from(flags.nonblock) * carrick_abi::LINUX_O_NONBLOCK)
                                    | (u64::from(flags.asynchronous) * carrick_abi::LINUX_O_ASYNC)
                                    | flags.immutable;
                                FamilyCompletion::Complete(out as i64)
                            }
                            Err(err) => map_fd_error(err),
                        }
                    }
                    carrick_abi::LINUX_F_SETFL => {
                        let (_, mut flags) = match venue.region.fd(NativeFdWait).getfl(table, old) {
                            Ok(pair) => pair,
                            Err(err) => return map_fd_error(err),
                        };
                        flags.append = arg & carrick_abi::LINUX_O_APPEND != 0;
                        flags.nonblock = arg & carrick_abi::LINUX_O_NONBLOCK != 0;
                        flags.asynchronous = arg & carrick_abi::LINUX_O_ASYNC != 0;
                        if let Err(err) = venue.region.fd(NativeFdWait).setfl(table, old, flags) {
                            return map_fd_error(err);
                        }
                        if let Some((handle, index)) = fd_map_lookup(self.fd_map, file_table, old.0)
                            && handle > 0
                            && handle & carrick_el1_abi::FD_HANDLE_INOTIFY_TAG == 0
                            && self.fd_map[index].fd_flags.load(Ordering::Acquire)
                                & FdMapSlot::HOST_VIEW
                                == 0
                            && let Some(open) = self.open_table.get((handle - 1) as usize)
                        {
                            if flags.append {
                                open.flags.fetch_or(
                                    carrick_el1_abi::DELEGATED_FLAG_APPEND,
                                    Ordering::Release,
                                );
                            } else {
                                open.flags.fetch_and(
                                    !carrick_el1_abi::DELEGATED_FLAG_APPEND,
                                    Ordering::Release,
                                );
                            }
                        }
                        FamilyCompletion::Complete(0)
                    }
                    _ => FamilyCompletion::Forward,
                }
            }
            _ => FamilyCompletion::Forward,
        }
    }

    fn ipc_transfer(&mut self) -> FamilyCompletion {
        let Some(venue) = self.ipc else {
            return FamilyCompletion::Forward;
        };
        let native_signals = self.process.is_some();
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
            let mut user = file::OwnerCopy {
                inner: file::ValidatedCopy {
                    task,
                    validator: &file::HardwareValidator,
                },
                owner: self.process.as_deref_mut(),
                wait: None,
            };
            let (disposition, sigpipe_owed) = ipc::serve_ipc_with_signals(
                &mut sched,
                frame,
                venue,
                &mut user,
                native_signals,
                &mut || false,
            );
            let result = frame.x[0] as i64;
            if sigpipe_owed {
                raise_native_sigpipe(self.process.as_deref_mut());
            }
            return carrick_personality_linux::dispatch::transfer_effect(
                &task.linux,
                orig_x0,
                result,
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
> carrick_personality_linux::sched::SchedVenue for El1PendingFamilies<'_, '_, F, C, U, G, Context>
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
    fn copy_in(&mut self, src: carrick_guest_arch::UserVa, dst: &mut [u8]) -> bool {
        #[cfg(test)]
        if let Some(user) = &mut self.lifecycle_user {
            return user.copy_in(dst, src.raw());
        }
        let Some(task) = self.current_tasks.get(self.frame.task_index()) else {
            return false;
        };
        crate::file::UserCopy::copy_in(
            &mut crate::file::ValidatedCopy {
                task,
                validator: &crate::file::HardwareValidator,
            },
            dst,
            src.raw(),
        )
    }
    fn guest_cpu_count(&self) -> usize {
        self.zone
            .as_ref()
            .and_then(|z| z.tables.carrier_cpu_count())
            .unwrap_or(0)
    }
    fn current_tid(&self) -> Option<u32> {
        let task = self.current_tasks.get(self.frame.task_index())?;
        let (_, control) = task.lifecycle_refs()?;
        control.visible_tid()
    }
    fn current_cpu(&self) -> Option<u32> {
        let slot = self.frame.slot()?;
        let zone = self.zone.as_ref()?;
        zone.tables.slot(slot).bound_cpu()
    }
    fn get_affinity(
        &self,
        pid: u32,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        let process = self
            .process
            .as_ref()
            .ok_or(carrick_syscall_abi::LINUX_ESRCH)?;
        process.get_affinity(pid)
    }
    fn set_affinity(
        &mut self,
        pid: u32,
        mask: carrick_core::affinity::CpuAffinity,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        let process = self
            .process
            .as_deref_mut()
            .ok_or(carrick_syscall_abi::LINUX_ESRCH)?;
        process.set_affinity(pid, mask)
    }
}

impl<
    F: Fn(u32) -> *mut u8,
    C: sched::ThreadCpu,
    U: sched::UserWord,
    G: GuestDispatchFrame,
    Context: DispatchContext,
> PendingFileVenue for El1PendingFamilies<'_, '_, F, C, U, G, Context>
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
    El1PendingFamilies<'_, '_, F, C, U, G, Context>
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
    use super::super::native_process_runtime::NativeThreadGroupOwner;
    use super::*;
    use carrick_test_support::GuestUserBuffer;
    use core::sync::atomic::Ordering;

    /// An SVC frame for syscall `nr` whose user pointers are guest user VAs
    /// (the harness check refuses a host pointer in `args`).
    fn svc_frame(nr: u64, args: &[u64]) -> TrapFrame {
        carrick_test_support::assert_guest_args(args);
        let mut frame = TrapFrame {
            esr: 0x15 << 26,
            ..TrapFrame::default()
        };
        frame.x[..args.len()].copy_from_slice(args);
        frame.x[8] = nr;
        frame
    }

    #[test]
    fn blocking_poll_without_a_wait_venue_does_not_publish_timeout_output() {
        let tasks = [CurrentTask::new()];
        let counters = Counters::default();
        let polls = GuestUserBuffer::from_value(super::super::file_table::PollFd {
            fd: -1,
            events: 1,
            revents: 0x1234,
        });
        let timeout = GuestUserBuffer::from_values(&[1i64, 0]);
        let mut frame = svc_frame(
            carrick_syscall_abi::nr::PPOLL.raw(),
            &[polls.arg(), 1, timeout.arg()],
        );
        frame.esr = 0;
        let mut pending = El1PendingFamilies {
            handoff: None,
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
            lifecycle: None,
            process: None::<&mut dyn carrick_personality_linux::lifecycle::ProcessNative>,
            source: None,
            anonymous: None,
            cache_lookup: |_| core::ptr::null_mut(),
        };
        assert_eq!(
            PendingFamilies::poll(&mut pending),
            FamilyCompletion::Forward
        );
        assert_eq!(
            polls.get::<super::super::file_table::PollFd>(0).revents,
            0x1234,
            "an incomplete readiness decision owns no output"
        );
    }

    #[test]
    fn production_trap_frame_routes_ppoll_to_the_poll_family() {
        let tasks = [CurrentTask::new()];
        tasks[0].set(
            carrick_el1_abi::El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(1),
            5,
        );
        tasks[0].mm.thread_generation.store(1, Ordering::Relaxed);
        let counters = Counters::default();
        let mut frame = TrapFrame::default();
        frame.x[8] = carrick_syscall_abi::nr::PPOLL.raw();
        frame.x[1] = 1025; // EINVAL is owned by poll, before touching a user pointer.
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
        assert_eq!(action, Action::Served);
        assert_eq!(frame.x[0] as i64, -22);
        assert_eq!(counters.served[73].load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused[73].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn native_service_refusals_keep_the_error_in_the_fatal_transport() {
        use super::super::native_process_runtime::NativeProcessError as Error;
        use carrick_el1_abi::EntryBindingFatalReason as Fatal;
        for (error, expected) in [
            (Error::Invalid, Fatal::NativeServiceInvalid),
            (Error::Stale, Fatal::NativeServiceStale),
            (Error::Exhausted, Fatal::NativeServiceExhausted),
            (Error::Fault, Fatal::NativeServiceFault),
            (Error::Unsupported, Fatal::NativeServiceUnsupported),
            (Error::GroupExitCustody, Fatal::NativeServiceGroupExit),
            (Error::Busy, Fatal::NativeServiceBusy),
            (Error::Quarantined, Fatal::NativeServiceQuarantined),
            (Error::NoChild, Fatal::NativeServiceNoChild),
        ] {
            let invariant = native_service_invariant(error);
            let reason = invariant.fatal_reason();
            assert_eq!(reason, expected);
            assert_eq!(Fatal::from_raw(reason as u64), Some(expected));
            assert_eq!(
                std::format!("{invariant:?}"),
                std::format!("NativeService({expected:?})")
            );
        }
    }

    #[test]
    fn stale_service_diagnostic_distinguishes_owners_without_reclassifying_busy() {
        use super::super::native_process_runtime::{
            NativeProcessError as Error, NativeServicePhase as Phase,
        };
        use carrick_el1_abi::EntryBindingFatalReason as Fatal;
        for (phase, expected) in [
            (Phase::Unspecified, Fatal::NativeServiceStale),
            (Phase::Capability, Fatal::NativeServiceCapStale),
            (Phase::Payload, Fatal::NativeServicePayloadStale),
            (Phase::Member, Fatal::NativeServiceMemberStale),
            (Phase::Birth, Fatal::NativeServiceBirthStale),
            (Phase::Mm, Fatal::NativeServiceMmStale),
            (Phase::Bind, Fatal::NativeServiceBindStale),
            (Phase::Publication, Fatal::NativeServicePublishStale),
            (Phase::Notice, Fatal::NativeServiceNoticeStale),
            (Phase::Park, Fatal::NativeServiceParkStale),
            (Phase::Completion, Fatal::NativeServiceCompleteStale),
            (Phase::Settlement, Fatal::NativeServiceSettleStale),
        ] {
            let reason = native_service_invariant_at(Error::Stale, phase).fatal_reason();
            assert_eq!(reason, expected);
            assert_eq!(Fatal::from_raw(reason as u64), Some(expected));
            assert_eq!(
                native_service_invariant_at(Error::Busy, phase).fatal_reason(),
                Fatal::NativeServiceBusy,
                "diagnostic provenance cannot turn contention into stale identity"
            );
        }
    }

    #[test]
    fn physical_custody_reasons_preserve_fatal_codes_and_debug_text() {
        use PhysicalCustodyInvariant as Custody;
        use carrick_el1_abi::EntryBindingFatalReason as Fatal;
        let cases = [
            (
                Custody::RootExitRefused,
                Fatal::RootExitRefused,
                "root exit crossing refused",
            ),
            (
                Custody::ForkCustodyRefused,
                Fatal::ForkCustodyRefused,
                "admitted fork custody commit refused",
            ),
            (
                Custody::AffinityTopologyMissing,
                Fatal::AffinityTopologyMissing,
                "affinity carrier topology missing after venue admission",
            ),
            (
                Custody::InventoryRollbackFailed,
                Fatal::PhysicalCustody,
                "unexposed physical inventory rollback failed",
            ),
        ];
        for (reason, expected, text) in cases {
            let invariant = NativeInvariant::PhysicalCustody(reason);
            assert_eq!(invariant.fatal_reason(), expected);
            assert_eq!(reason.as_str(), text);
            assert_eq!(
                std::format!("{invariant:?}"),
                std::format!("PhysicalCustody({text:?})")
            );
        }
        use carrick_core_abi::NativeRunFailureReason as Run;
        for reason in [
            Run::X86GroupExitCustody,
            Run::NativeInvalid,
            Run::NativeStale,
            Run::NativeExhausted,
            Run::NativeFault,
            Run::NativeUnsupported,
            Run::NativeBusy,
            Run::NativeQuarantined,
            Run::NativeNoChild,
            Run::BirthSettlement,
            Run::ClaimRollback,
            Run::BornEnqueueRefused,
        ] {
            let custody = Custody::NativeRunFailure(reason);
            let invariant = NativeInvariant::PhysicalCustody(custody);
            assert_eq!(invariant.fatal_reason(), Fatal::PhysicalCustody);
            assert_eq!(custody.as_str(), reason.as_str());
            assert_eq!(
                std::format!("{invariant:?}"),
                std::format!("PhysicalCustody({:?})", reason.as_str())
            );
        }
    }

    #[test]
    fn native_exec_capture_stages_before_releasing_the_ring_lane() {
        let task = CurrentTask::new();
        let path = GuestUserBuffer::from_bytes(b"/bin/static\0");
        let arg = GuestUserBuffer::from_bytes(b"static\0");
        let env = GuestUserBuffer::from_bytes(b"A=B\0");
        let argv = GuestUserBuffer::from_values(&[arg.arg(), 0]);
        let envp = GuestUserBuffer::from_values(&[env.arg(), 0]);
        let frame = svc_frame(221, &[path.arg(), argv.arg(), envp.arg()]);

        let payload = match native_exec_stage(&frame, &task).unwrap() {
            NativeExecStage::Payload(payload) => payload,
            NativeExecStage::Fault(fault) => {
                panic!("resident exec payload faulted at {:?}", fault.address)
            }
            NativeExecStage::Failed(errno) => {
                panic!("resident exec payload failed with {errno:?}")
            }
        };
        let view = carrick_core_abi::service::ExecPayloadView::parse(&payload).unwrap();
        assert_eq!(view.path(), b"/bin/static");
        assert_eq!(view.argv().collect::<alloc::vec::Vec<_>>(), [b"static"]);
        assert_eq!(view.envp().collect::<alloc::vec::Vec<_>>(), [b"A=B"]);
    }

    #[test]
    fn native_host_file_stage_keeps_in_zone_writes_in_ring_and_stages_host_stdout() {
        use carrick_personality_linux::native_host_file::{
            DescriptionAccess, HostFileStage, InZoneKind,
        };
        struct Resident;
        impl file::MemoryValidator for Resident {
            fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
            fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
        }
        let task = CurrentTask::new();
        let bytes = b"bin\nboot\n";
        let mut frame = TrapFrame {
            esr: 0x15 << 26,
            ..TrapFrame::default()
        };
        frame.x[8] = 64;
        frame.x[0] = 1;
        frame.x[1] = bytes.as_ptr().addr() as u64;
        frame.x[2] = bytes.len() as u64;
        let table = [3, 4, 5];

        // The same write to an in-zone pipe never builds a host request.
        let mut asked = None;
        assert_eq!(
            native_host_file_stage(
                &frame,
                &task,
                &Resident,
                table,
                |fd| {
                    asked = Some(fd);
                    Some(NativeDescriptor::InZone(InZoneKind::Pipe))
                },
                &mut |_| 0
            ),
            Some(HostFileStage::InRing)
        );
        assert_eq!(asked, Some(1), "the caller's own fd is resolved");

        // Host stdout crosses with the caller's bytes and table.
        let Some(HostFileStage::Request {
            mut record,
            output,
            resolves_path,
            map,
            ..
        }) = native_host_file_stage(
            &frame,
            &task,
            &Resident,
            table,
            |_| {
                Some(NativeDescriptor::HostBacked {
                    access: DescriptionAccess::ReadWrite,
                })
            },
            &mut |_| panic!("a write releases no mapping sources"),
        )
        else {
            panic!("a host-backed stdout write crosses");
        };
        assert_eq!(output, None);
        assert_eq!(map, None, "a write stashes no mapping source");
        assert!(!resolves_path);
        let view = carrick_core_abi::host_file::HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(view.input(), bytes);
        assert_eq!(view.header().table, table);

        // A contended namespace keeps the call's old route, and a non-SVC
        // exit is never a host-file call.
        assert_eq!(
            native_host_file_stage(&frame, &task, &Resident, table, |_| None, &mut |_| 0),
            None
        );
        frame.esr = 0x24 << 26;
        assert_eq!(
            native_host_file_stage(
                &frame,
                &task,
                &Resident,
                table,
                |_| { panic!("a fault never resolves descriptors") },
                &mut |_| 0
            ),
            None
        );
    }

    /// #894: Rust std's startup `ppoll` over host-bound fds 0-2 (no events,
    /// zero timeout) from a native child. Its in-ring owner leaves the set
    /// unrouted (only the carrier observes host descriptions); the native
    /// venue must stage it as one readiness snapshot instead of letting it
    /// reach the carrier as a bare crossing that is refused with ENOSYS.
    #[test]
    fn native_ppoll_over_host_stdio_crosses_as_a_readiness_snapshot() {
        use carrick_personality_linux::native_host_file::{
            DescriptionAccess, HostFileStage, InZoneKind,
        };
        struct Resident;
        impl file::MemoryValidator for Resident {
            fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
            fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
        }
        let task = CurrentTask::new();
        let mut pollfds = [0u8; 24];
        for (fd, entry) in pollfds.chunks_exact_mut(8).enumerate() {
            entry[..4].copy_from_slice(&(fd as i32).to_le_bytes());
        }
        let timespec = [0u8; 16];
        let mut frame = TrapFrame {
            esr: 0x15 << 26,
            ..TrapFrame::default()
        };
        frame.x[8] = carrick_syscall_abi::nr::PPOLL.raw();
        frame.x[0] = pollfds.as_mut_ptr().addr() as u64;
        frame.x[1] = 3;
        frame.x[2] = timespec.as_ptr().addr() as u64;
        frame.x[3] = 0;
        frame.x[4] = 8;
        let table = [3, 4, 5];
        let host = |_| {
            Some(NativeDescriptor::HostBacked {
                access: DescriptionAccess::ReadWrite,
            })
        };
        let Some(HostFileStage::Request {
            mut record,
            output,
            resolves_path,
            map,
            chdir,
        }) = native_host_file_stage(&frame, &task, &Resident, table, host, &mut |_| {
            panic!("a poll releases no mapping sources")
        })
        else {
            panic!("a host-bound ppoll from a native process must stage a readiness snapshot");
        };
        assert!(!resolves_path && map.is_none() && !chdir);
        let output = output.expect("the pollfd array is the reply");
        assert_eq!(output.address, frame.x[0]);
        assert_eq!(output.len, pollfds.len());
        let view = carrick_core_abi::host_file::HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(
            view.header().op,
            carrick_core_abi::host_file::HostFileOp::Poll
        );
        assert_eq!(view.header().table, table);
        assert_eq!(
            view.header().args[0],
            carrick_core_abi::host_file::PollWait::Snapshot.raw()
        );
        assert_eq!(view.input(), pollfds);
        // The carrier's snapshot: stderr has hung up.
        let mut reply = pollfds;
        reply[22..24].copy_from_slice(&carrick_syscall_abi::LINUX_POLLHUP.to_le_bytes());
        view.reply(1, &reply).unwrap();
        let result = carrick_personality_linux::native_host_file::complete(
            &record,
            Some(output),
            &mut |address, bytes| {
                assert_eq!(address, pollfds.as_ptr().addr() as u64);
                pollfds.copy_from_slice(bytes);
                true
            },
        );
        assert_eq!(result.raw(), 1, "readiness, not ENOSYS");
        assert_eq!(pollfds, reply);

        // A mixed set keeps its route: the carrier cannot observe the pipe.
        assert_eq!(
            native_host_file_stage(
                &frame,
                &task,
                &Resident,
                table,
                |fd| Some(if fd == 0 {
                    NativeDescriptor::InZone(InZoneKind::Pipe)
                } else {
                    NativeDescriptor::HostBacked {
                        access: DescriptionAccess::ReadWrite,
                    }
                }),
                &mut |_| 0
            ),
            None
        );
    }

    #[test]
    fn native_exec_capture_routes_a_nonresident_argument_to_fault_supply() {
        struct RefusePage(u64);

        impl file::MemoryValidator for RefusePage {
            fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }

            fn readable_bytes(&self, user_va: u64, len: usize) -> usize {
                if user_va & !4095 == self.0 & !4095 {
                    0
                } else {
                    len
                }
            }
        }

        let task = CurrentTask::new();
        let path = b"/bin/static\0";
        let arg = b"static\0";
        let argv = [arg.as_ptr().addr() as u64, 0];
        let envp = [0_u64];
        let mut frame = TrapFrame {
            esr: 0x15 << 26,
            ..TrapFrame::default()
        };
        frame.x[8] = 221;
        frame.x[0] = path.as_ptr().addr() as u64;
        frame.x[1] = argv.as_ptr().addr() as u64;
        frame.x[2] = envp.as_ptr().addr() as u64;

        let request = crate::exec_stage::ExecStageRequest {
            call: carrick_core_abi::service::ExecCall::Execve,
            path: frame.x[0],
            argv: frame.x[1],
            envp: frame.x[2],
        };
        let staged = native_exec_stage_request(&task, &RefusePage(frame.x[1]), request).unwrap();
        let NativeExecStage::Fault(fault) = staged else {
            panic!("nonresident argv did not select page supply");
        };
        assert_eq!(fault.address.raw(), frame.x[1]);
        assert_eq!(fault.access, carrick_guest_arch::Access::Read);
        assert!(!fault.present);
    }

    #[test]
    fn host_loaded_arm_task_keeps_terminal_calls_on_legacy_route() {
        assert!(
            !arm_process_call_claimed(94, 0, || NativeThreadGroupOwner::Unowned),
            "exit_group"
        );
        assert!(
            !arm_process_call_claimed(93, 0, || NativeThreadGroupOwner::Unowned),
            "exit"
        );
        assert!(
            !arm_process_call_claimed(95, 0, || NativeThreadGroupOwner::Unowned),
            "waitid"
        );
        assert!(
            arm_process_call_claimed(220, 0, || NativeThreadGroupOwner::Unowned),
            "first fork"
        );
        assert!(
            arm_process_call_claimed(94, 0, || NativeThreadGroupOwner::ForkChild),
            "native child exit"
        );
        assert!(
            arm_process_call_claimed(93, 0, || NativeThreadGroupOwner::ForkChild),
            "native thread exit"
        );
        assert!(
            arm_process_call_claimed(95, 0, || NativeThreadGroupOwner::ForkChild),
            "native child waitid"
        );
        // Only a ring-owned fork child's execve is the owner's: a root or
        // host-loaded task execs through the host with its live authority.
        assert!(
            arm_process_call_claimed(221, 0, || NativeThreadGroupOwner::ForkChild),
            "native child execve"
        );
        for owner in [
            NativeThreadGroupOwner::Root,
            NativeThreadGroupOwner::Unowned,
        ] {
            assert!(
                !arm_process_call_claimed(221, 0, || owner),
                "{owner:?} execve"
            );
        }
        // execveat follows execve (#1530): a fork child has no host task,
        // so its execveat is the native owner's, never a host exit.
        assert!(
            arm_process_call_claimed(281, 0, || NativeThreadGroupOwner::ForkChild),
            "native child execveat"
        );
        for owner in [
            NativeThreadGroupOwner::Root,
            NativeThreadGroupOwner::Unowned,
        ] {
            assert!(
                !arm_process_call_claimed(281, 0, || owner),
                "{owner:?} execveat"
            );
        }
        assert!(!arm_process_call_claimed(62, 0, || panic!(
            "ordinary lseek queried registry"
        )));
    }

    /// `fexecve` from a native fork child (#1530): libc issues
    /// `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. Before, the owner left
    /// it unclaimed, so it left the guest as a raw host syscall exit with no
    /// host task to serve it, and the carrier died. Now it is claimed, it
    /// stages as the descriptor form of the exec request, and any syscall a
    /// fork child's owner leaves unclaimed is a counted ENOSYS in ring.
    #[test]
    fn native_fork_child_fexecve_is_claimed_staged_and_never_a_host_exit() {
        use super::super::native_process_runtime::NativeThreadGroupOwner;

        // Claimed for the fork child, as the production gate asks it.
        assert!(arm_process_call_claimed(281, 0, || {
            NativeThreadGroupOwner::ForkChild
        }));

        // Staged with the descriptor and flags, and an empty path.
        struct Resident;
        impl file::MemoryValidator for Resident {
            fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
            fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
                len
            }
        }
        let task = CurrentTask::new();
        let empty = b"\0";
        let arg = b"sh\0";
        let argv = [arg.as_ptr().addr() as u64, 0];
        let envp = [0_u64];
        let mut frame = TrapFrame {
            esr: 0x15 << 26,
            ..TrapFrame::default()
        };
        frame.x[8] = 281;
        frame.x[0] = 3;
        frame.x[1] = empty.as_ptr().addr() as u64;
        frame.x[2] = argv.as_ptr().addr() as u64;
        frame.x[3] = envp.as_ptr().addr() as u64;
        frame.x[4] = carrick_abi::LINUX_AT_EMPTY_PATH;
        let request = crate::exec_stage::ExecStageRequest {
            call: carrick_core_abi::service::ExecCall::Execveat {
                dirfd: frame.x[0] as i32,
                flags: frame.x[4] as u32,
            },
            path: frame.x[1],
            argv: frame.x[2],
            envp: frame.x[3],
        };
        let Some(NativeExecStage::Payload(payload)) =
            native_exec_stage_request(&task, &Resident, request)
        else {
            panic!("fexecve did not stage an exec request");
        };
        let view = carrick_core_abi::service::ExecPayloadView::parse(&payload).unwrap();
        assert_eq!(
            view.call(),
            carrick_core_abi::service::ExecCall::Execveat {
                dirfd: 3,
                flags: carrick_abi::LINUX_AT_EMPTY_PATH as u32
            }
        );
        assert!(view.path().is_empty());

        // The one route decision for an unclaimed native syscall: a fork
        // child (no host task) is answered in ring; a root keeps the host.
        assert_eq!(
            unclaimed_native_syscall(NativeThreadGroupOwner::ForkChild),
            UnclaimedNativeSyscall::CountedEnosys
        );
        for owner in [
            NativeThreadGroupOwner::Root,
            NativeThreadGroupOwner::Unowned,
        ] {
            assert_eq!(
                unclaimed_native_syscall(owner),
                UnclaimedNativeSyscall::HostRoute
            );
        }
        let counters = Counters::new();
        assert_eq!(
            refuse_unclaimed_native_syscall(&mut frame, &counters),
            Action::Served
        );
        assert_eq!(frame.x[0] as i64, -38);
        assert_eq!(counters.refused[281].load(Ordering::Relaxed), 1);
    }

    /// #1941: a fork child's admitted private futex wake always finishes in
    /// ring. A forward of one reaching the final capture is the typed
    /// invariant break, never the counted ENOSYS that lost the child's wake.
    /// An admitted wait may legitimately decline (timed while switched in,
    /// exhausted entry pool) and keeps the counted ENOSYS, as does an
    /// unported futex operation; a root keeps its host route.
    #[test]
    fn native_fork_child_futex_wake_forward_is_an_invariant_break() {
        use super::super::native_process_runtime::NativeThreadGroupOwner;
        use carrick_core_abi::service::ServiceOperation;
        use carrick_personality_linux::sched::{
            FUTEX_WAIT_PRIVATE, FUTEX_WAKE_BITSET_PRIVATE, FUTEX_WAKE_PRIVATE,
        };

        let futex = |op: u64, count: u64, mask: u64| {
            let mut frame = TrapFrame {
                esr: 0x15 << 26,
                ..TrapFrame::default()
            };
            frame.x[8] = 98;
            frame.x[0] = 0x2d9e18;
            frame.x[1] = op;
            frame.x[2] = count;
            frame.x[5] = mask;
            frame
        };
        let task = CurrentTask::new();
        for mut frame in [
            futex(FUTEX_WAKE_PRIVATE, 1, 0),
            futex(FUTEX_WAKE_BITSET_PRIVATE, 1, u64::from(u32::MAX)),
        ] {
            let counters = Counters::new();
            assert_eq!(
                native_unstaged_exit(
                    &mut frame,
                    &task.linux,
                    Action::Forward,
                    || NativeThreadGroupOwner::ForkChild,
                    &counters,
                ),
                NativeUnstagedExit::OwnedFamilyForward,
                "op {:#x}",
                frame.x[1]
            );
            assert_eq!(frame.x[0], 0x2d9e18, "no errno written");
            assert_eq!(counters.refused[98].load(Ordering::Relaxed), 0);
            assert_eq!(counters.refused_child[98].load(Ordering::Relaxed), 0);
        }
        assert_eq!(
            NativeInvariant::OwnedFamilyForward.fatal_reason(),
            carrick_el1_abi::EntryBindingFatalReason::OwnedFamilyForward
        );
        assert_eq!(
            carrick_el1_abi::EntryBindingFatalReason::from_raw(
                carrick_el1_abi::EntryBindingFatalReason::OwnedFamilyForward as u64
            ),
            Some(carrick_el1_abi::EntryBindingFatalReason::OwnedFamilyForward)
        );

        // An admitted wait's decline and an operation the family does not
        // serve (FUTEX_REQUEUE_PRIVATE) keep the counted ENOSYS.
        for op in [FUTEX_WAIT_PRIVATE, 128 | 3] {
            let counters = Counters::new();
            let mut frame = futex(op, 1, 0);
            assert_eq!(
                native_unstaged_exit(
                    &mut frame,
                    &task.linux,
                    Action::Forward,
                    || NativeThreadGroupOwner::ForkChild,
                    &counters,
                ),
                NativeUnstagedExit::Refused(Action::Served),
                "op {op:#x}"
            );
            assert_eq!(frame.x[0] as i64, -38);
            assert_eq!(counters.refused_child[98].load(Ordering::Relaxed), 1);
        }

        // A root keeps its host route for the same call.
        let counters = Counters::new();
        let mut frame = futex(FUTEX_WAKE_PRIVATE, 1, 0);
        assert!(matches!(
            native_unstaged_exit(
                &mut frame,
                &task.linux,
                Action::Forward,
                || NativeThreadGroupOwner::Root,
                &counters,
            ),
            NativeUnstagedExit::Operation(ServiceOperation::Crossing { .. })
        ));
        assert_eq!(counters.refused[98].load(Ordering::Relaxed), 0);
    }

    /// The production order of an owned native entry no stage served
    /// (#1530): the unclaimed-syscall decision runs before the crossing
    /// capture, so a fork child's unclaimed call is one counted in-ring
    /// ENOSYS and never also a carrier crossing. Red if the crossing capture
    /// wins: the fork child's call would park as `Crossing`.
    #[test]
    fn native_fork_child_unclaimed_syscall_is_refused_before_any_crossing() {
        use super::super::native_process_runtime::NativeThreadGroupOwner;
        use carrick_core_abi::service::ServiceOperation;
        use carrick_guest_arch::NativeOrdinal;

        let svc = |nr: u64| {
            let mut frame = TrapFrame {
                esr: 0x15 << 26,
                ..TrapFrame::default()
            };
            frame.x[8] = nr;
            frame.x[0] = 0xfeed;
            frame
        };
        let task = CurrentTask::new();

        // A fork child: refused in ring, counted once, no operation.
        let counters = Counters::new();
        let mut frame = svc(451);
        assert_eq!(
            native_unstaged_exit(
                &mut frame,
                &task.linux,
                Action::Forward,
                || NativeThreadGroupOwner::ForkChild,
                &counters,
            ),
            NativeUnstagedExit::Refused(Action::Served)
        );
        assert_eq!(frame.x[0] as i64, -38);
        assert_eq!(counters.refused[451].load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused_child[451].load(Ordering::Relaxed), 1);
        assert_eq!(counters.venue_refused[451].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[451].load(Ordering::Relaxed), 1);

        // A root or unadmitted task keeps its crossing; nothing is counted.
        for owner in [
            NativeThreadGroupOwner::Root,
            NativeThreadGroupOwner::Unowned,
        ] {
            let counters = Counters::new();
            let mut frame = svc(451);
            assert_eq!(
                native_unstaged_exit(
                    &mut frame,
                    &task.linux,
                    Action::Forward,
                    || owner,
                    &counters
                ),
                NativeUnstagedExit::Operation(ServiceOperation::Crossing {
                    ordinal: NativeOrdinal::new(451)
                })
            );
            assert_eq!(frame.x[0], 0xfeed);
            assert_eq!(counters.refused[451].load(Ordering::Relaxed), 0);
        }

        // Not a syscall: a fork child's breakpoint stays its exception
        // service, and the owner is never asked.
        let counters = Counters::new();
        let mut frame = TrapFrame {
            esr: 0x3c << 26,
            ..TrapFrame::default()
        };
        assert!(matches!(
            native_unstaged_exit(
                &mut frame,
                &task.linux,
                Action::Forward,
                || panic!("an exception asks no syscall route"),
                &counters,
            ),
            NativeUnstagedExit::Operation(ServiceOperation::Exception(_))
        ));
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
                            self.zone.wake_placed(
                                &guard,
                                mm,
                                address,
                                u32::MAX,
                                1,
                                carrick_sched_core::Waker::El1 { slot },
                                &mut [],
                                &mut effects
                            ),
                            1
                        );
                        drop(guard);
                        assert!(self.zone.switch_in(slot).is_some());
                    }
                    _ => {
                        self.zone.clear_current(slot);
                        self.zone.free_record(self.record);
                        let replacement = self.zone.alloc_record(self.identity).unwrap();
                        assert!(self.zone.requeue_preempted(slot, replacement).is_queued());
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
                        assert!(zone.requeue_preempted(slot, record).is_queued());
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
                            assert!(zone.requeue_preempted(slot, successor).is_queued());
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
                                    '_,
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

        let action = dispatch_entry(&mut frame, &counters, &mut None);
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
        assert_eq!(
            dispatch_entry(&mut frame, &counters, &mut None),
            Action::Forward
        );
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    /// #1502: the vector now enters EL1 for every EL0 synchronous
    /// exception. A BRK, an undefined instruction, an alignment or an FP
    /// trap is never a syscall: its x8 is whatever the program left there,
    /// and dispatching it as one would run (and return from) a call the
    /// program never made. It forwards unserved, so a ring-owned process's
    /// native owner captures it as its exception service and a host task's
    /// exception leaves through `hvc #2` exactly as before.
    #[test]
    fn el0_sync_exceptions_forward_without_dispatching_x8() {
        for esr in [
            0x3c << 26 | 0x1234, // brk #0x1234
            1 << 25,             // undefined instruction (EC 0)
            0x22 << 26,          // PC alignment
            0x26 << 26,          // SP alignment
            0x07 << 26,          // FP access
            0x2c << 26,          // FP exception
            0x32 << 26,          // software step
            0x30 << 26,          // hardware breakpoint
        ] {
            let counters = Counters::default();
            let mut frame = TrapFrame {
                esr,
                elr: 0x40_1000,
                x: {
                    let mut x = [0u64; 31];
                    x[8] = 172; // SYS_getpid, as a program might leave it
                    x
                },
                ..TrapFrame::default()
            };
            let action = dispatch_entry(&mut frame, &counters, &mut None);
            assert_eq!(action, Action::Forward, "esr={esr:#x}");
            assert_eq!(frame.x[0], 0, "esr={esr:#x}: no call result");
            assert_eq!(frame.elr, 0x40_1000, "esr={esr:#x}: no replay");
            assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
            assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
            assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn test_dispatch_entry_routes_irq() {
        let counters = Counters::default();
        let mut frame = TrapFrame {
            esr: 0,
            ..TrapFrame::default()
        };

        let action = dispatch_entry(&mut frame, &counters, &mut None);
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

        let action = dispatch_entry(&mut frame, &counters, &mut None);
        assert_eq!(action, Action::Served);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn affinity_without_process_authority_uses_counted_refusal() {
        use carrick_personality_linux::dispatch::CompletionRoute;
        let tasks = [CurrentTask::new()];
        tasks[0].set(
            carrick_el1_abi::El1TaskId::from_linux_tid(41),
            carrick_el1_abi::SnapshotGeneration::from_raw(11),
            5,
        );
        for (ordinal, pid) in [(122, 0), (122, 41), (123, 0), (123, 41)] {
            let counters = Counters::default();
            let mut mask = 1u64;
            let mut frame = TrapFrame::default();
            frame.x[8] = ordinal;
            frame.x[0] = pid;
            frame.x[1] = 8;
            frame.x[2] = (&mut mask as *mut u64) as u64;
            let route = dispatch_syscall_with_native(
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
                None::<&mut dyn lifecycle::ProcessNative<'_, carrick_sched_core::ThreadCtx>>,
                None,
                None,
                |_| core::ptr::null_mut(),
            );
            assert_eq!(route, CompletionRoute::Served);
            assert_eq!(frame.x[0] as i64, -38, "ordinal {ordinal}, pid {pid}");
            assert_eq!(
                counters.refused[ordinal as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(counters.served[ordinal as usize].load(Ordering::Relaxed), 0);
            assert_eq!(mask, 1);
        }
    }

    #[test]
    fn el1_sched_venue_carrier_topology_and_missing_authority() {
        use carrick_personality_linux::sched::SchedVenue;

        let layout = std::alloc::Layout::new::<ZoneTables>();
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!ptr.is_null());
            std::boxed::Box::from_raw(ptr)
        };
        zone.publish_carrier_cpu_count(4);
        // Executor occupancy is not the installed carrier topology.
        for cpu in 0..4 {
            let slot = SlotId::new(cpu);
            zone.drive(slot, 1);
            zone.publish_slot(slot, 1, Some(cpu as u32), 0);
        }
        assert_eq!(zone.carrier_cpu_count(), Some(4));
        assert_eq!(zone.carrier_affinity_mask(), Some(0x0f));
        zone.publish_slot(SlotId::new(3), 0, None, 0);
        assert_eq!(zone.carrier_cpu_count(), Some(4));
        assert_eq!(zone.carrier_affinity_mask(), Some(0x0f));

        let counters = Counters::default();
        let mut cpu = sched::FakeCpu::default();
        let tasks = [CurrentTask::new()];
        let mut frame = TrapFrame::default();
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
                user: &sched::HardwareUserWord,
            }),
            ipc: None,
            lifecycle: None,
            process: None::<
                &mut dyn carrick_personality_linux::lifecycle::ProcessNative<
                    '_,
                    carrick_sched_core::ThreadCtx,
                >,
            >,
            source: None,
            anonymous: None,
            cache_lookup: |_| core::ptr::null_mut(),
        };

        // Venue reports the installed count despite an unpublished executor.
        assert_eq!(pending.guest_cpu_count(), 4);

        // No process authority must decline before interpreting affinity args.
        for ordinal in [122, 123] {
            pending.frame.x[8] = ordinal;
            pending.frame.x[0] = 0;
            pending.frame.x[1] = 8;
            pending.frame.x[2] = 0x2000;
            assert!(PendingFamilies::sched_venue(&mut pending).is_none());
        }
        pending.frame.x[8] = 124;
        assert!(PendingFamilies::sched_venue(&mut pending).is_some());
    }

    #[test]
    fn native_host_file_staging_refusal_is_counted_once() {
        use carrick_personality_linux::native_host_file::{DescriptionAccess, HostFileStage};
        struct Resident;
        impl file::MemoryValidator for Resident {
            fn writable_bytes(&self, _: u64, len: usize) -> usize {
                len
            }
            fn readable_bytes(&self, _: u64, len: usize) -> usize {
                len
            }
        }
        let task = CurrentTask::new();
        let path = b"relative\0";
        for child in [false, true] {
            let counters = Counters::default();
            let mut frame = TrapFrame {
                esr: 0x15 << 26,
                ..TrapFrame::default()
            };
            frame.x[8] = 56; // openat relative to a host directory
            frame.x[0] = 3;
            frame.x[1] = path.as_ptr().addr() as u64;
            let Some(HostFileStage::Returned(result)) = native_host_file_stage(
                &frame,
                &task,
                &Resident,
                [3, 4, 5],
                |_| {
                    Some(NativeDescriptor::HostBacked {
                        access: DescriptionAccess::ReadWrite,
                    })
                },
                &mut |_| panic!("openat releases no mappings"),
            ) else {
                panic!("relative host-dirfd staging must refuse");
            };
            assert_eq!(
                result.raw(),
                carrick_syscall_abi::LINUX_ENOSYS.guest_retval()
            );
            assert_eq!(
                native_host_file_return(
                    result.raw(),
                    carrick_guest_arch::NativeOrdinal::new(frame.x[8]),
                    &counters,
                    || child
                ),
                result.raw()
            );
            let snapshot = counters.copy_snapshot();
            assert_eq!(snapshot.refused[56].load(Ordering::Relaxed), 1);
            assert_eq!(
                snapshot.refused_child[56].load(Ordering::Relaxed),
                u64::from(child)
            );
            assert_eq!(snapshot.venue_refused[56].load(Ordering::Relaxed), 0);
            assert_eq!(snapshot.served[56].load(Ordering::Relaxed), 1);
            // Ordinary staging errors are answers, not refusals.
            native_host_file_return(
                carrick_syscall_abi::LINUX_EBADF.guest_retval(),
                carrick_guest_arch::NativeOrdinal::new(56),
                &counters,
                || child,
            );
            assert_eq!(counters.refused[56].load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn traced_native_exec_is_refused_with_counted_eperm() {
        let task = CurrentTask::new();
        task.publish_ptrace_traced(true);
        let counters = Counters::default();
        for ordinal in [221, 281] {
            let mut frame = TrapFrame::default();
            frame.x[8] = ordinal;
            assert!(refuse_traced_native_exec(
                &mut frame,
                &task,
                &counters,
                || true
            ));
            assert_eq!(
                frame.x[0] as i64,
                carrick_syscall_abi::LINUX_EPERM.guest_retval()
            );
            assert_eq!(
                counters.refused[ordinal as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(counters.served[ordinal as usize].load(Ordering::Relaxed), 1);
        }
        task.publish_ptrace_traced(false);
        let mut frame = TrapFrame::default();
        frame.x[8] = 221;
        assert!(!refuse_traced_native_exec(
            &mut frame,
            &task,
            &counters,
            || true
        ));
    }
}
