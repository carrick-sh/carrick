//! The single Linux ordinal-to-family routing table.
use crate::abi::entry::SyscallResult;
use crate::identity::IdentityCall;
use crate::lifecycle::{LifecycleCall, LifecycleOutcome};
use crate::sysinfo::SysinfoCall;
use carrick_core_abi::EntryContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnonymousCall {
    Brk,
    Munmap,
    Mremap,
    Mmap,
    Mprotect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Anonymous(AnonymousCall),
    Read,
    Write,
    EpollWait,
    Lifecycle(LifecycleCall),
    Signal(crate::signal::SignalCall),
    Futex,
    InotifyAdd,
    InotifyRemove,
    FileSeek,
    FilePositioned,
    AllocatorControl,
    SignalReturn,
    Identity(IdentityCall),
    Sysinfo(SysinfoCall),
    Unported,
}

/// A family implementation reports semantic progress; only this Linux owner
/// turns it into the entry's completion/continuation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamilyCompletion {
    Complete(i64),
    CompleteWithWork(i64),
    Switched(i64),
    SwitchedWithWork(i64),
    AccountedSwitched(i64),
    CommitOwed(i64),
    Suspended,
    Forward,
    Handback,
    AccountedComplete(i64),
    AccountedForward,
    AccountedSuspended,
}

/// Retained IPC/futex progress before the single entry owner settles the turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcServed {
    Forward,
    Returned { switched: bool },
    Idle,
    Handback,
}

impl From<carrick_core_abi::Served> for IpcServed {
    fn from(served: carrick_core_abi::Served) -> Self {
        match served {
            carrick_core_abi::Served::Returned { switched } => Self::Returned { switched },
            carrick_core_abi::Served::Idle => Self::Idle,
        }
    }
}

/// Preserve already-accounted MM work without completing a parked/switch turn.
pub fn accounted_scheduler_effect(
    served: carrick_core_abi::Served,
    result: i64,
) -> FamilyCompletion {
    match served {
        carrick_core_abi::Served::Returned { switched: true } => {
            FamilyCompletion::AccountedSwitched(result)
        }
        carrick_core_abi::Served::Returned { switched: false } => {
            FamilyCompletion::AccountedComplete(result)
        }
        carrick_core_abi::Served::Idle => FamilyCompletion::AccountedSuspended,
    }
}

/// A switched frame belongs to its successor; only an unswitched return records
/// this call's original argument. Park/handback cannot fall through to file I/O.
pub fn transfer_effect(
    task: &crate::abi::entry::LinuxTaskState,
    original: u64,
    result: i64,
    disposition: IpcServed,
) -> FamilyCompletion {
    match disposition {
        IpcServed::Returned { switched: false } => {
            task.orig_arg0
                .store(original, core::sync::atomic::Ordering::Relaxed);
            FamilyCompletion::Complete(result)
        }
        IpcServed::Returned { switched: true } => FamilyCompletion::Switched(result),
        IpcServed::Idle => FamilyCompletion::Suspended,
        IpcServed::Forward => FamilyCompletion::Forward,
        IpcServed::Handback => FamilyCompletion::Handback,
    }
}

/// The test-control primitive already accounts its own diagnostic completion.
/// Pending work retains the original argument without fabricating task admission.
pub fn allocator_effect(
    task: Option<&crate::abi::entry::LinuxTaskState>,
    original: u64,
    result: crate::abi::entry::SyscallResult,
) -> FamilyCompletion {
    if let Some(task) = task
        && task.has_pending_host_work()
    {
        task.orig_arg0
            .store(original, core::sync::atomic::Ordering::Relaxed);
        return FamilyCompletion::CompleteWithWork(result.raw());
    }
    FamilyCompletion::AccountedComplete(result.raw())
}

/// Diagnostic lowering for the lifecycle entry-work refusal.
#[derive(Clone, Copy)]
pub struct LifecycleWorkCounters<'a> {
    pub exit: &'a core::sync::atomic::AtomicU64,
    pub clone: &'a core::sync::atomic::AtomicU64,
}
impl LifecycleWorkCounters<'_> {
    pub fn declined(&self, ordinal: u64) {
        let counter = match ordinal {
            93 => self.exit,
            220 => self.clone,
            _ => return,
        };
        counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Borrowed diagnostic arrays; Linux owns their ordinal indexing/publication.
#[derive(Clone, Copy)]
pub struct EntryCounters<'a> {
    pub served: &'a [core::sync::atomic::AtomicU64],
    pub forwarded: &'a [core::sync::atomic::AtomicU64],
}
impl EntryCounters<'_> {
    pub fn served(&self, ordinal: u64) {
        if let Some(counter) = self.served.get(ordinal as usize) {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    pub fn forwarded(&self, ordinal: u64) {
        if let Some(counter) = self.forwarded.get(ordinal as usize) {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Temporary order-5 seam for families whose bodies move in orders 6-9.
/// Methods disappear with their named order; implementations never select a
/// different family and never publish entry completion.
pub trait PendingFamilies<'a, C: EntryContext + 'a = carrick_sched_core::ThreadCtx> {
    fn take_handoff_receipt(&mut self) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
        None
    }
    fn binding(&self) -> Option<carrick_core_abi::ExecutionBinding>;
    fn record_source(&self) -> Option<carrick_core_abi::BornInZoneSource<'a, C>> {
        None
    }
    fn anonymous_venue(
        &mut self,
    ) -> Option<&mut dyn crate::pending_anonymous::PendingAnonymousVenue> {
        None
    }
    fn file_venue(&mut self) -> Option<&mut dyn crate::pending_file::PendingFileVenue> {
        None
    }
    fn task_state(&self) -> Option<&crate::abi::entry::LinuxTaskState> {
        None
    }
    fn entry_counters(&self) -> Option<EntryCounters<'_>> {
        None
    }
    fn prepare_anonymous(&mut self) -> Option<FamilyCompletion> {
        self.anonymous_venue()?.park_prepared()
    }
    fn host_work(&self) -> bool {
        self.task_state()
            .is_some_and(crate::abi::entry::LinuxTaskState::has_pending_host_work)
    }
    fn resumes_operation(&self) -> bool {
        false
    }
    fn ipc_available(&self) -> bool {
        false
    }
    fn lifecycle_available(&self) -> bool {
        false
    }
    fn lifecycle_work_counters(&self) -> Option<LifecycleWorkCounters<'_>> {
        None
    }
    fn anonymous_declined_for_work(&self, _: u64) {}
    fn declined_for_work(&self, ordinal: u64) {
        if let Some(counters) = self.lifecycle_work_counters() {
            counters.declined(ordinal);
        }
        self.anonymous_declined_for_work(ordinal);
    }
    fn record_served(&self, ordinal: u64) {
        if let Some(counters) = self.entry_counters() {
            counters.served(ordinal);
        }
    }
    fn record_forwarded(&self, ordinal: u64) {
        if let Some(counters) = self.entry_counters() {
            counters.forwarded(ordinal);
        }
    }
    /// Host crossing set governing which syscalls may forward to the host.
    fn crossing_set(&self) -> crate::crossing::HostCrossingSet;
    /// Whether this context enforces its ISA's unported-call allowlist.
    fn ring_first_strict(&self) -> bool {
        false
    }
    /// Captured guest-native ordinal; absent frames count in the unknown bucket.
    fn native_number(&self) -> Option<carrick_syscall_abi::NativeNr> {
        None
    }
    /// Access to the refusal counters array, if available.
    fn refused_counters(&self) -> Option<&'a [core::sync::atomic::AtomicU64]> {
        None
    }
    fn publish_forward_work(&self, original_argument0: u64) {
        if let Some(task) = self.task_state() {
            // No family ran: after owed work drains the host must execute the
            // original syscall, never treat its argument register as a result.
            task.record_commit_owed(original_argument0);
        }
    }
    fn publish_work(&self, commit: bool) {
        if let Some(task) = self.task_state() {
            if commit {
                task.record_commit_owed(task.orig_arg0.load(core::sync::atomic::Ordering::Relaxed));
            } else {
                task.record_completed_with_work();
            }
        }
    }
    fn file_write(&mut self) -> FamilyCompletion {
        self.file_seek()
    }

    /// Removed by order 7.
    fn anonymous(&mut self, call: AnonymousCall) -> FamilyCompletion {
        self.anonymous_venue()
            .map_or(FamilyCompletion::Forward, |venue| {
                crate::pending_anonymous::serve(call, venue)
            })
    }
    /// Removed by order 8.
    fn read(&mut self) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
    /// Removed by order 8.
    fn write(&mut self) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
    /// Removed by order 8.
    fn epoll_wait(&mut self) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
    fn lifecycle_native(&mut self) -> Option<&mut dyn crate::lifecycle::LifecycleNative<'a>> {
        None
    }
    fn identity_native(&mut self) -> Option<&mut dyn crate::identity::IdentityNative<'a>> {
        None
    }
    fn sysinfo_native(&mut self) -> Option<&mut dyn crate::sysinfo::SysinfoNative<'a>> {
        None
    }
    fn signal_native(&mut self) -> Option<&mut dyn crate::signal::SignalNative<'a>> {
        None
    }
    fn original_argument0(&self) -> u64;
    fn install_result(&mut self, result: SyscallResult);
    /// Removed by order 8.
    fn futex(&mut self) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
    /// Removed by order 9.
    fn inotify_add(&mut self) -> FamilyCompletion {
        self.file_venue()
            .map_or(FamilyCompletion::Forward, |venue| {
                let original = venue.original_argument0();
                let result = venue.inotify_add();
                crate::pending_file::watch_effect(
                    venue,
                    result,
                    original,
                    crate::pending_file::WatchEffect::Added,
                )
            })
    }
    /// Removed by order 9.
    fn inotify_remove(&mut self) -> FamilyCompletion {
        self.file_venue()
            .map_or(FamilyCompletion::Forward, |venue| {
                let original = venue.original_argument0();
                let result = venue.inotify_remove();
                crate::pending_file::watch_effect(
                    venue,
                    result,
                    original,
                    crate::pending_file::WatchEffect::Removed,
                )
            })
    }
    /// Removed by order 9.
    fn file_read(&mut self) -> FamilyCompletion {
        self.file_venue()
            .map_or(FamilyCompletion::Forward, crate::pending_file::serve_read)
    }
    /// Removed by order 9.
    fn file_seek(&mut self) -> FamilyCompletion {
        self.file_venue()
            .map_or(FamilyCompletion::Forward, |venue| {
                let ordinal = venue.ordinal();
                crate::pending_file::serve_file(venue, ordinal)
            })
    }
    /// Removed by order 9.
    fn file_positioned(&mut self, _: u64) -> FamilyCompletion {
        self.file_seek()
    }
    /// Test-only allocator family, removed with its control ABI.
    fn allocator_control(&mut self) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
}

/// The sole ordinal routing decision and family completion owner.
fn serve_family<'a, C: EntryContext + 'a>(
    family: Family,
    ordinal: u64,
    pending: &mut dyn PendingFamilies<'a, C>,
) -> FamilyRun {
    if let Family::Lifecycle(call) = family {
        let original = pending.original_argument0();
        return pending
            .lifecycle_native()
            .and_then(|native| crate::lifecycle::invoke(call, native))
            .map_or(FamilyCompletion::Forward.into(), |outcome| {
                let returned = match outcome {
                    LifecycleOutcome::Returned { result, .. } => Some((result, original)),
                    LifecycleOutcome::Transferred { .. } => None,
                };
                FamilyRun {
                    completion: crate::lifecycle::lifecycle_effect(&outcome),
                    returned,
                    forward_reason: ForwardReason::FamilyFallback,
                }
            });
    }
    if let Family::Identity(call) = family {
        let original = pending.original_argument0();
        return pending
            .identity_native()
            .and_then(|native| crate::identity::invoke(call, native))
            .map_or(
                FamilyRun {
                    completion: FamilyCompletion::Forward,
                    returned: None,
                    // An absent/unported owner must still enter crossing policy.
                    forward_reason: ForwardReason::Unported,
                },
                |result| FamilyRun {
                    completion: FamilyCompletion::Complete(result.raw()),
                    returned: Some((result, original)),
                    forward_reason: ForwardReason::FamilyFallback,
                },
            );
    }
    if let Family::Sysinfo(call) = family {
        let original = pending.original_argument0();
        return pending
            .sysinfo_native()
            .and_then(|native| crate::sysinfo::invoke(call, native))
            .map_or(
                FamilyRun {
                    completion: FamilyCompletion::Forward,
                    returned: None,
                    // An absent/unported owner must still enter crossing policy.
                    forward_reason: ForwardReason::Unported,
                },
                |result| FamilyRun {
                    completion: FamilyCompletion::Complete(result.raw()),
                    returned: Some((result, original)),
                    forward_reason: ForwardReason::FamilyFallback,
                },
            );
    }
    if let Family::Signal(call) = family {
        let original = pending.original_argument0();
        return pending
            .signal_native()
            .and_then(|native| crate::signal::invoke(call, native))
            .map_or(FamilyCompletion::Forward.into(), |outcome| {
                let returned = match outcome {
                    crate::signal::SignalOutcome::Returned { result, .. } => {
                        Some((result, original))
                    }
                    crate::signal::SignalOutcome::Transferred { .. } => None,
                };
                FamilyRun {
                    completion: crate::signal::signal_effect(&outcome),
                    returned,
                }
            });
    }
    let mut returned = None;
    let completion = match family {
        Family::Anonymous(call) => {
            // A native venue can retain a separate operation frame. Transport
            // its completed result through the same authenticated finish as
            // lifecycle results; never replay or alter a switched context.
            let original = pending.original_argument0();
            let completion = pending.anonymous(call);
            returned = match completion {
                FamilyCompletion::Complete(value)
                | FamilyCompletion::CompleteWithWork(value)
                | FamilyCompletion::AccountedComplete(value)
                | FamilyCompletion::CommitOwed(value) => {
                    Some((SyscallResult::new(value), original))
                }
                _ => None,
            };
            completion
        }
        Family::Read => pending.read(),
        Family::Write => pending.write(),
        Family::EpollWait => pending.epoll_wait(),
        Family::Lifecycle(_) => FamilyCompletion::Forward,
        Family::Identity(_) => FamilyCompletion::Forward,
        Family::Sysinfo(_) => FamilyCompletion::Forward,
        Family::Signal(_) => FamilyCompletion::Forward,
        Family::Futex => pending.futex(),
        Family::InotifyAdd => pending.inotify_add(),
        Family::InotifyRemove => pending.inotify_remove(),
        Family::FileSeek => pending.file_seek(),
        Family::FilePositioned => pending.file_positioned(ordinal),
        Family::AllocatorControl => pending.allocator_control(),
        Family::SignalReturn => FamilyCompletion::Handback,
        Family::Unported => FamilyCompletion::Forward,
    };
    FamilyRun {
        completion,
        returned,
        forward_reason: if family == Family::Unported {
            ForwardReason::Unported
        } else {
            ForwardReason::FamilyFallback
        },
    }
}

/// Route one AArch64 Linux ordinal. Family implementations are temporary
/// EL1 traits until orders 6-9 move their semantic bodies; they never choose
/// another family or own completion.
pub const fn route_aarch64(ordinal: u64, allocator_control: u64) -> Family {
    match ordinal {
        214 => Family::Anonymous(AnonymousCall::Brk),
        215 => Family::Anonymous(AnonymousCall::Munmap),
        216 => Family::Anonymous(AnonymousCall::Mremap),
        222 => Family::Anonymous(AnonymousCall::Mmap),
        226 => Family::Anonymous(AnonymousCall::Mprotect),
        63 => Family::Read,
        64 => Family::Write,
        22 => Family::EpollWait,
        62 => Family::FileSeek,
        67 | 68 => Family::FilePositioned,
        27 => Family::InotifyAdd,
        28 => Family::InotifyRemove,
        98 => Family::Futex,
        93 => Family::Lifecycle(LifecycleCall::Exit),
        129 => Family::Signal(crate::signal::SignalCall::Kill),
        130 => Family::Signal(crate::signal::SignalCall::Tkill),
        131 => Family::Signal(crate::signal::SignalCall::Tgkill),
        132 => Family::Lifecycle(LifecycleCall::SigAltStack),
        133 => Family::Signal(crate::signal::SignalCall::RtSigsuspend),
        134 => Family::Signal(crate::signal::SignalCall::RtSigaction),
        135 => Family::Lifecycle(LifecycleCall::SigProcMask),
        136 => Family::Signal(crate::signal::SignalCall::RtSigpending),
        137 => Family::Signal(crate::signal::SignalCall::RtSigtimedwait),
        138 => Family::Signal(crate::signal::SignalCall::RtSigqueueinfo),
        139 => Family::Signal(crate::signal::SignalCall::RtSigreturn),
        240 => Family::Signal(crate::signal::SignalCall::RtTgsigqueueinfo),
        424 => Family::Signal(crate::signal::SignalCall::PidfdSendSignal),
        99 => Family::Lifecycle(LifecycleCall::SetRobustList),
        178 => Family::Lifecycle(LifecycleCall::GetTid),
        172 => Family::Lifecycle(LifecycleCall::GetPid),
        220 => Family::Lifecycle(LifecycleCall::Clone),
        nr if nr == carrick_syscall_abi::nr::WAIT4.raw() => Family::Lifecycle(LifecycleCall::Wait4),
        nr if nr == carrick_syscall_abi::nr::EXIT_GROUP.raw() => {
            Family::Lifecycle(LifecycleCall::ExitGroup)
        }
        nr if nr == carrick_syscall_abi::nr::CAPGET.raw() => Family::Identity(IdentityCall::CapGet),
        nr if nr == carrick_syscall_abi::nr::CAPSET.raw() => Family::Identity(IdentityCall::CapSet),
        nr if nr == carrick_syscall_abi::nr::PERSONALITY.raw() => {
            Family::Identity(IdentityCall::Personality)
        }
        nr if nr == carrick_syscall_abi::nr::SET_TID_ADDRESS.raw() => {
            Family::Identity(IdentityCall::SetTidAddress)
        }
        nr if nr == carrick_syscall_abi::nr::GET_ROBUST_LIST.raw() => {
            Family::Identity(IdentityCall::GetRobustList)
        }
        nr if nr == carrick_syscall_abi::nr::SETREGID.raw() => {
            Family::Identity(IdentityCall::SetReGid)
        }
        nr if nr == carrick_syscall_abi::nr::SETGID.raw() => Family::Identity(IdentityCall::SetGid),
        nr if nr == carrick_syscall_abi::nr::SETREUID.raw() => {
            Family::Identity(IdentityCall::SetReUid)
        }
        nr if nr == carrick_syscall_abi::nr::SETUID.raw() => Family::Identity(IdentityCall::SetUid),
        nr if nr == carrick_syscall_abi::nr::SETRESUID.raw() => {
            Family::Identity(IdentityCall::SetResUid)
        }
        nr if nr == carrick_syscall_abi::nr::GETRESUID.raw() => {
            Family::Identity(IdentityCall::GetResUid)
        }
        nr if nr == carrick_syscall_abi::nr::SETRESGID.raw() => {
            Family::Identity(IdentityCall::SetResGid)
        }
        nr if nr == carrick_syscall_abi::nr::GETRESGID.raw() => {
            Family::Identity(IdentityCall::GetResGid)
        }
        nr if nr == carrick_syscall_abi::nr::SETFSUID.raw() => {
            Family::Identity(IdentityCall::SetFsUid)
        }
        nr if nr == carrick_syscall_abi::nr::SETFSGID.raw() => {
            Family::Identity(IdentityCall::SetFsGid)
        }
        nr if nr == carrick_syscall_abi::nr::SETPGID.raw() => {
            Family::Identity(IdentityCall::SetPgid)
        }
        nr if nr == carrick_syscall_abi::nr::GETPGID.raw() => {
            Family::Identity(IdentityCall::GetPgid)
        }
        nr if nr == carrick_syscall_abi::nr::GETSID.raw() => Family::Identity(IdentityCall::GetSid),
        nr if nr == carrick_syscall_abi::nr::SETSID.raw() => Family::Identity(IdentityCall::SetSid),
        nr if nr == carrick_syscall_abi::nr::GETGROUPS.raw() => {
            Family::Identity(IdentityCall::GetGroups)
        }
        nr if nr == carrick_syscall_abi::nr::SETGROUPS.raw() => {
            Family::Identity(IdentityCall::SetGroups)
        }
        nr if nr == carrick_syscall_abi::nr::UNAME.raw() => Family::Sysinfo(SysinfoCall::Uname),
        nr if nr == carrick_syscall_abi::nr::SETHOSTNAME.raw() => {
            Family::Sysinfo(SysinfoCall::SetHostname)
        }
        nr if nr == carrick_syscall_abi::nr::SETDOMAINNAME.raw() => {
            Family::Sysinfo(SysinfoCall::SetDomainname)
        }
        nr if nr == carrick_syscall_abi::nr::GETRLIMIT.raw() => {
            Family::Sysinfo(SysinfoCall::GetRlimit)
        }
        nr if nr == carrick_syscall_abi::nr::SETRLIMIT.raw() => {
            Family::Sysinfo(SysinfoCall::SetRlimit)
        }
        nr if nr == carrick_syscall_abi::nr::GETRUSAGE.raw() => {
            Family::Sysinfo(SysinfoCall::GetRusage)
        }
        nr if nr == carrick_syscall_abi::nr::UMASK.raw() => Family::Sysinfo(SysinfoCall::Umask),
        nr if nr == carrick_syscall_abi::nr::PRCTL.raw() => Family::Identity(IdentityCall::Prctl),
        nr if nr == carrick_syscall_abi::nr::GETPPID.raw() => {
            Family::Identity(IdentityCall::GetPpid)
        }
        nr if nr == carrick_syscall_abi::nr::GETUID.raw() => Family::Identity(IdentityCall::GetUid),
        nr if nr == carrick_syscall_abi::nr::GETEUID.raw() => {
            Family::Identity(IdentityCall::GetEuid)
        }
        nr if nr == carrick_syscall_abi::nr::GETGID.raw() => Family::Identity(IdentityCall::GetGid),
        nr if nr == carrick_syscall_abi::nr::GETEGID.raw() => {
            Family::Identity(IdentityCall::GetEgid)
        }
        nr if nr == carrick_syscall_abi::nr::SYSINFO.raw() => Family::Sysinfo(SysinfoCall::Sysinfo),
        nr if nr == carrick_syscall_abi::nr::PRLIMIT64.raw() => {
            Family::Sysinfo(SysinfoCall::Prlimit64)
        }
        nr if allocator_control != u64::MAX && nr == allocator_control => Family::AllocatorControl,
        _ => Family::Unported,
    }
}

/// Return transport selected by the Linux completion owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionRoute {
    Served,
    WithWork,
    Suspended,
    Forward,
    InvalidCompletion,
}

/// Linux return-work ordering, shared by common entry and pending families.
pub fn completion_route(completion: FamilyCompletion, pending: bool) -> CompletionRoute {
    match completion {
        FamilyCompletion::Complete(_) | FamilyCompletion::Switched(_) if pending => {
            CompletionRoute::WithWork
        }
        FamilyCompletion::Complete(_)
        | FamilyCompletion::AccountedComplete(_)
        | FamilyCompletion::Switched(_)
        | FamilyCompletion::AccountedSwitched(_) => CompletionRoute::Served,
        FamilyCompletion::CompleteWithWork(_)
        | FamilyCompletion::SwitchedWithWork(_)
        | FamilyCompletion::CommitOwed(_) => CompletionRoute::WithWork,
        FamilyCompletion::Suspended | FamilyCompletion::AccountedSuspended => {
            CompletionRoute::Suspended
        }
        FamilyCompletion::Forward
        | FamilyCompletion::Handback
        | FamilyCompletion::AccountedForward => CompletionRoute::Forward,
    }
}

// The retained allocator-test transport previously runs without a loaded task.
// It is an explicitly enabled diagnostic, never a guest Linux admission and
// never a fabricated task/MM identity. Its routing still has this one owner.
enum CompletionAuthority<'a, C: EntryContext> {
    Entry(carrick_core_abi::EntryCompletion<'a, C>),
    BornInZone(carrick_core_abi::BornEntryCompletion<'a, C>),
    AllocatorDiagnostic,
}

/// Whether a call has an in-ring family. ARM admits unported crossings;
/// x86 admits every forwarding completion through its eight-crossing set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardReason {
    Unported,
    FamilyFallback,
}

struct FamilyRun {
    forward_reason: ForwardReason,
    completion: FamilyCompletion,
    returned: Option<(SyscallResult, u64)>,
}
impl From<FamilyCompletion> for FamilyRun {
    fn from(completion: FamilyCompletion) -> Self {
        Self {
            completion,
            returned: None,
            forward_reason: ForwardReason::FamilyFallback,
        }
    }
}

fn finish<'a, C: EntryContext + 'a>(
    ordinal: u64,
    original_argument0: u64,
    run: FamilyRun,
    pending: &mut dyn PendingFamilies<'a, C>,
    authority: CompletionAuthority<'a, C>,
) -> CompletionRoute {
    let result = run.completion;
    let transfers = matches!(
        result,
        FamilyCompletion::Suspended
            | FamilyCompletion::AccountedSuspended
            | FamilyCompletion::Switched(_)
            | FamilyCompletion::SwitchedWithWork(_)
            | FamilyCompletion::AccountedSwitched(_)
    );
    let authenticated = match authority {
        CompletionAuthority::Entry(token) if transfers => pending
            .take_handoff_receipt()
            .is_some_and(|receipt| carrick_core::entry::handoff(token, receipt).is_ok()),
        CompletionAuthority::BornInZone(token) if transfers => {
            pending.take_handoff_receipt().is_some_and(|receipt| {
                carrick_core::entry::handoff_born_in_zone(token, receipt).is_ok()
            })
        }
        CompletionAuthority::Entry(token) => pending.binding().is_some_and(|live| {
            carrick_core::entry::complete(token, live, pending.record_source()).is_ok()
        }),
        CompletionAuthority::BornInZone(token) => pending
            .binding()
            .zip(pending.record_source())
            .is_some_and(|(live, source)| {
                carrick_core::entry::complete_born_in_zone(token, live, source).is_ok()
            }),
        CompletionAuthority::AllocatorDiagnostic => true,
    };
    if !authenticated {
        return CompletionRoute::InvalidCompletion;
    }
    if let Some((value, original)) = run.returned {
        pending.install_result(value);
        if let Some(task) = pending.task_state() {
            task.orig_arg0
                .store(original, core::sync::atomic::Ordering::Relaxed);
        }
    }
    if (result == FamilyCompletion::Forward && run.forward_reason == ForwardReason::Unported)
        || (pending.crossing_set() == crate::crossing::HostCrossingSet::X86
            && matches!(
                result,
                FamilyCompletion::Forward
                    | FamilyCompletion::AccountedForward
                    | FamilyCompletion::Handback
            ))
    {
        let canonical = carrick_syscall_abi::CanonicalNr::new(ordinal);
        let crossing_set = pending.crossing_set();
        let ring_first_strict = pending.ring_first_strict();
        let counters = pending.refused_counters();
        let decision = crate::crossing::evaluate_host_crossing(
            crossing_set,
            ring_first_strict,
            Some(canonical),
            pending.native_number(),
            counters,
            |ret| pending.install_result(ret),
        );
        if decision == crate::crossing::HostCrossingDecision::Refused {
            if pending.host_work() {
                pending.publish_work(false);
                return CompletionRoute::WithWork;
            }
            return CompletionRoute::Served;
        }
    }
    // Only an effect-free strict ARM decline can use the host replay boundary.
    // Handback retains its operation; AccountedForward has already run its
    // family. The x86 WORK_PORT has no replay transport.
    let replay = pending.ring_first_strict()
        && pending.host_work()
        && pending.crossing_set() == crate::crossing::HostCrossingSet::Aarch64
        && result == FamilyCompletion::Forward;
    let route = if replay {
        CompletionRoute::WithWork
    } else {
        completion_route(result, pending.host_work())
    };
    match result {
        FamilyCompletion::AccountedComplete(_)
        | FamilyCompletion::AccountedSwitched(_)
        | FamilyCompletion::AccountedForward
        | FamilyCompletion::AccountedSuspended => {}
        FamilyCompletion::Forward | FamilyCompletion::Handback => pending.record_forwarded(ordinal),
        _ => pending.record_served(ordinal),
    }
    if route == CompletionRoute::WithWork {
        if replay {
            pending.publish_forward_work(original_argument0);
        } else {
            pending.publish_work(matches!(result, FamilyCompletion::CommitOwed(_)));
        }
    }
    route
}

/// One routing and completion owner. A retained IPC operation is offered to
/// its family before any fresh descriptor lookup, even with return work pending.
pub fn dispatch<'a, C: EntryContext + 'a>(
    ordinal: u64,
    control: u64,
    pending: &mut dyn PendingFamilies<'a, C>,
) -> CompletionRoute {
    let original_argument0 = pending.original_argument0();
    let family = route_aarch64(ordinal, control);
    let completion = match pending.binding().and_then(|binding| {
        if let Some(token) = carrick_core::entry::admit(binding, pending.record_source()) {
            Some(CompletionAuthority::Entry(token))
        } else {
            pending
                .record_source()
                .and_then(|source| carrick_core::entry::admit_born_in_zone(binding, source))
                .map(CompletionAuthority::BornInZone)
        }
    }) {
        Some(authority) => authority,
        None if family == Family::AllocatorControl => CompletionAuthority::AllocatorDiagnostic,
        None => {
            let set = pending.crossing_set();
            let strict = pending.ring_first_strict();
            let counters = pending.refused_counters();
            let decision = crate::crossing::evaluate_host_crossing(
                set,
                strict,
                Some(carrick_syscall_abi::CanonicalNr::new(ordinal)),
                pending.native_number(),
                counters,
                |ret| pending.install_result(ret),
            );
            if decision == crate::crossing::HostCrossingDecision::Refused {
                return CompletionRoute::Served;
            }
            pending.record_forwarded(ordinal);
            return CompletionRoute::Forward;
        }
    };
    if matches!(family, Family::Anonymous(_))
        && let Some(result) = pending.prepare_anonymous()
    {
        return finish(
            ordinal,
            original_argument0,
            result.into(),
            pending,
            completion,
        );
    }
    let setup = pending.lifecycle_available()
        && matches!(family, Family::Lifecycle(_))
        && matches!(ordinal, 99 | 132 | 135);
    let transfer = pending.ipc_available()
        && matches!(family, Family::Read | Family::Write | Family::EpollWait);
    // Identity/resource operations complete synchronously under their owner.
    // Serve them before handing back metadata work; an absent owner still
    // declines through Unported crossing policy, never host identity replay.
    let owned_identity = matches!(family, Family::Identity(_) | Family::Sysinfo(_));
    if pending.host_work() && !pending.resumes_operation() && !transfer && !setup && !owned_identity
    {
        pending.declined_for_work(ordinal);
        return finish(
            ordinal,
            original_argument0,
            FamilyRun {
                completion: FamilyCompletion::Forward,
                returned: None,
                forward_reason: if family == Family::Unported {
                    ForwardReason::Unported
                } else {
                    ForwardReason::FamilyFallback
                },
            },
            pending,
            completion,
        );
    }
    let mut result = serve_family(family, ordinal, pending);
    if result.completion != FamilyCompletion::Forward {
        return finish(ordinal, original_argument0, result, pending, completion);
    }
    if pending.host_work() && !setup {
        pending.declined_for_work(ordinal);
        return finish(ordinal, original_argument0, result, pending, completion);
    }
    // File fallback follows the IPC authority's explicit decline, never a
    // retained operation's handback or completion.
    result = match family {
        Family::Read => pending.file_read().into(),
        Family::Write => pending.file_write().into(),
        _ => result,
    };
    finish(ordinal, original_argument0, result, pending, completion)
}

/// The anonymous family retains an owned operation until settlement; only a
/// completed return or explicit decline publishes an entry counter.
pub enum ReservationDecision<W, R> {
    Forward,
    Return(i64),
    Work(W),
    Unavailable(R),
}
pub fn dispatch_anonymous<W, R>(
    decision: ReservationDecision<W, R>,
    record: impl FnOnce(bool),
) -> ReservationDecision<W, R> {
    match &decision {
        ReservationDecision::Forward => record(false),
        ReservationDecision::Return(_) => record(true),
        ReservationDecision::Work(_) | ReservationDecision::Unavailable(_) => {}
    }
    decision
}

#[cfg(test)]
mod ring_first_tests {
    use super::*;
    use crate::crossing::HostCrossingSet;
    use carrick_core_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    // No lifecycle or process venue: a terminal call still belongs to the
    // carrier, just as in x86's crossing set, until native custody serves it.
    struct CarrierOwned<'a> {
        set: HostCrossingSet,
        mutate_forward: bool,
        strict: bool,
        state: crate::abi::entry::LinuxTaskState,
        result: i64,
        native: carrick_syscall_abi::NativeNr,
        admitted: bool,
        work: bool,
        handback: bool,
        refused: &'a [AtomicU64; 513],
        forwarded: [AtomicU64; 512],
    }
    impl<'a> PendingFamilies<'a> for CarrierOwned<'a> {
        fn binding(&self) -> Option<ExecutionBinding> {
            if !self.admitted {
                return None;
            }
            Some(ExecutionBinding {
                task: EntryTaskKey::from_raw(1),
                generation: EntryGeneration::from_raw(1),
                mm: EntryMmKey::from_raw(1),
                thread_generation: EntryThreadGeneration::from_raw(1),
            })
        }
        fn native_number(&self) -> Option<carrick_syscall_abi::NativeNr> {
            Some(self.native)
        }
        fn task_state(&self) -> Option<&crate::abi::entry::LinuxTaskState> {
            Some(&self.state)
        }
        fn host_work(&self) -> bool {
            self.work
        }
        fn resumes_operation(&self) -> bool {
            self.handback
        }
        fn prepare_anonymous(&mut self) -> Option<FamilyCompletion> {
            self.handback.then_some(FamilyCompletion::Handback)
        }
        fn futex(&mut self) -> FamilyCompletion {
            if self.mutate_forward {
                self.result = 0xbeef;
                self.work = true;
            }
            if self.handback {
                FamilyCompletion::Handback
            } else {
                FamilyCompletion::Forward
            }
        }
        fn crossing_set(&self) -> HostCrossingSet {
            self.set
        }
        fn ring_first_strict(&self) -> bool {
            self.strict
        }
        fn refused_counters(&self) -> Option<&'a [AtomicU64]> {
            Some(self.refused)
        }
        fn original_argument0(&self) -> u64 {
            self.result as u64
        }
        fn install_result(&mut self, result: SyscallResult) {
            self.result = result.raw();
        }
        fn record_forwarded(&self, nr: u64) {
            self.forwarded[nr as usize].fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn failed_entry_admission_cannot_bypass_crossing_policy() {
        let refused = [const { AtomicU64::new(0) }; 513];
        let mut pending = CarrierOwned {
            set: HostCrossingSet::Aarch64,
            mutate_forward: false,
            strict: true,
            state: crate::abi::entry::LinuxTaskState::new(),
            native: carrick_syscall_abi::NativeNr(174),
            admitted: false,
            result: 42,
            work: false,
            handback: false,
            refused: &refused,
            forwarded: [const { AtomicU64::new(0) }; 512],
        };
        assert_eq!(
            dispatch(174, u64::MAX, &mut pending),
            CompletionRoute::Served
        );
        assert_eq!(pending.forwarded[174].load(Ordering::Relaxed), 0);
        assert_eq!(pending.result, -38);
        assert_eq!(pending.refused[174].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn strict_arm_preserves_family_declines_handback_and_owed_work() {
        for (ordinal, work, handback, expected) in [
            (222, false, false, CompletionRoute::Forward),
            (226, false, false, CompletionRoute::Forward),
            (215, false, false, CompletionRoute::Forward),
            (27, false, false, CompletionRoute::Forward),
            (98, false, false, CompletionRoute::Forward),
            (98, false, true, CompletionRoute::Forward),
            (98, true, true, CompletionRoute::Forward),
            (222, true, true, CompletionRoute::Forward),
            (139, false, false, CompletionRoute::Forward),
            (220, false, false, CompletionRoute::Forward),
            (260, false, false, CompletionRoute::Forward),
            (174, true, false, CompletionRoute::WithWork),
        ] {
            let refused = [const { AtomicU64::new(0) }; 513];
            let mut pending = CarrierOwned {
                set: HostCrossingSet::Aarch64,
                mutate_forward: false,
                strict: true,
                state: crate::abi::entry::LinuxTaskState::new(),
                native: carrick_syscall_abi::NativeNr(ordinal),
                admitted: true,
                result: 42,
                work,
                handback,
                refused: &refused,
                forwarded: [const { AtomicU64::new(0) }; 512],
            };
            assert_eq!(
                dispatch(ordinal, u64::MAX, &mut pending),
                expected,
                "ordinal={ordinal} work={work} handback={handback}"
            );
            if ordinal == 174 {
                assert_eq!(
                    pending.result, -38,
                    "pending work must not leak host getuid"
                );
                assert_eq!(pending.refused[174].load(Ordering::Relaxed), 1);
                assert_eq!(pending.forwarded[174].load(Ordering::Relaxed), 0);
                assert_eq!(
                    pending.state.take_served_boundary(),
                    Some(crate::abi::entry::ServedBoundary::Completed)
                );
            } else {
                assert_eq!(pending.result, 42);
                assert_eq!(pending.refused[ordinal as usize].load(Ordering::Relaxed), 0);
            }
        }
    }

    #[test]
    fn owed_work_does_not_replay_handback_accounted_forward_or_x86() {
        for (set, completion) in [
            (HostCrossingSet::Aarch64, FamilyCompletion::Handback),
            (HostCrossingSet::Aarch64, FamilyCompletion::AccountedForward),
            (HostCrossingSet::X86, FamilyCompletion::Forward),
        ] {
            let refused = [const { AtomicU64::new(0) }; 513];
            let mut pending = CarrierOwned {
                set,
                mutate_forward: false,
                strict: true,
                state: crate::abi::entry::LinuxTaskState::new(),
                native: carrick_syscall_abi::NativeNr(0),
                admitted: true,
                result: 42,
                work: true,
                handback: false,
                refused: &refused,
                forwarded: [const { AtomicU64::new(0) }; 512],
            };
            assert_eq!(
                finish(
                    63,
                    42,
                    completion.into(),
                    &mut pending,
                    CompletionAuthority::AllocatorDiagnostic
                ),
                CompletionRoute::Forward,
                "{set:?} {completion:?}"
            );
            assert_eq!(
                pending.state.take_served_boundary(),
                None,
                "forward transport must not publish replay"
            );
        }
    }

    #[test]
    fn opt_out_arm_family_declines_with_work_keep_plain_forward() {
        for ordinal in [222, 98, 220, 260, 174, 160] {
            let refused = [const { AtomicU64::new(0) }; 513];
            let mut pending = CarrierOwned {
                set: HostCrossingSet::Aarch64,
                mutate_forward: false,
                strict: false,
                state: crate::abi::entry::LinuxTaskState::new(),
                native: carrick_syscall_abi::NativeNr(ordinal),
                admitted: true,
                result: 42,
                work: true,
                handback: false,
                refused: &refused,
                forwarded: [const { AtomicU64::new(0) }; 512],
            };
            assert_eq!(
                dispatch(ordinal, u64::MAX, &mut pending),
                CompletionRoute::Forward,
                "ordinal={ordinal} opt-out must retain main's transport"
            );
            assert_eq!(pending.state.take_served_boundary(), None);
            assert_eq!(
                pending.forwarded[ordinal as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(pending.refused[ordinal as usize].load(Ordering::Relaxed), 0);
            assert_eq!(pending.result, 42);
            assert!(pending.host_work(), "forward must retain owed host work");
        }
    }

    #[test]
    fn no_effect_arm_forward_replays_saved_argument_not_mutated_frame() {
        let refused = [const { AtomicU64::new(0) }; 513];
        let mut pending = CarrierOwned {
            set: HostCrossingSet::Aarch64,
            mutate_forward: true,
            strict: true,
            state: crate::abi::entry::LinuxTaskState::new(),
            native: carrick_syscall_abi::NativeNr(98),
            admitted: true,
            result: 42,
            work: false,
            handback: false,
            refused: &refused,
            forwarded: [const { AtomicU64::new(0) }; 512],
        };
        assert_eq!(
            dispatch(98, u64::MAX, &mut pending),
            CompletionRoute::WithWork
        );
        assert_eq!(pending.result, 0xbeef);
        assert_eq!(
            pending.state.take_served_boundary(),
            Some(crate::abi::entry::ServedBoundary::ReplayOriginal { x0: 42 })
        );
    }

    #[test]
    fn strict_arm_terminal_calls_without_process_owner_cross_to_carrier() {
        for ordinal in [93, 94] {
            let refused = [const { AtomicU64::new(0) }; 513];
            let mut pending = CarrierOwned {
                set: HostCrossingSet::Aarch64,
                mutate_forward: false,
                strict: true,
                state: crate::abi::entry::LinuxTaskState::new(),
                native: carrick_syscall_abi::NativeNr(ordinal),
                admitted: true,
                result: 42,
                work: false,
                handback: false,
                refused: &refused,
                forwarded: [const { AtomicU64::new(0) }; 512],
            };
            assert_eq!(
                dispatch(ordinal, u64::MAX, &mut pending),
                CompletionRoute::Forward
            );
            assert_eq!(pending.result, 42, "exit status must reach the carrier");
            assert_eq!(
                pending.forwarded[ordinal as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(pending.refused[ordinal as usize].load(Ordering::Relaxed), 0);
        }
    }
}
