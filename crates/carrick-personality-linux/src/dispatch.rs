//! The single Linux ordinal-to-family routing table.

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
    Lifecycle,
    Futex,
    InotifyAdd,
    InotifyRemove,
    FileSeek,
    FilePositioned,
    AllocatorControl,
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
pub trait PendingFamilies<'a> {
    fn binding(&self) -> Option<carrick_core_abi::ExecutionBinding>;
    fn record_source(&self) -> Option<carrick_core_abi::BornInZoneSource<'a>> {
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
    /// Removed by order 6.
    fn lifecycle(&mut self, _: u64) -> FamilyCompletion {
        FamilyCompletion::Forward
    }
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
fn serve_family(
    family: Family,
    ordinal: u64,
    pending: &mut dyn PendingFamilies<'_>,
) -> FamilyCompletion {
    match family {
        Family::Anonymous(call) => pending.anonymous(call),
        Family::Read => pending.read(),
        Family::Write => pending.write(),
        Family::EpollWait => pending.epoll_wait(),
        Family::Lifecycle => pending.lifecycle(ordinal),
        Family::Futex => pending.futex(),
        Family::InotifyAdd => pending.inotify_add(),
        Family::InotifyRemove => pending.inotify_remove(),
        Family::FileSeek => pending.file_seek(),
        Family::FilePositioned => pending.file_positioned(ordinal),
        Family::AllocatorControl => pending.allocator_control(),
        Family::Unported => FamilyCompletion::Forward,
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
        93 | 132 | 135 | 99 | 178 | 220 => Family::Lifecycle,
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
enum CompletionAuthority<'a> {
    Entry(carrick_core_abi::EntryCompletion),
    BornInZone(carrick_core_abi::BornEntryCompletion<'a>),
    AllocatorDiagnostic,
}

fn finish<'a>(
    ordinal: u64,
    result: FamilyCompletion,
    pending: &dyn PendingFamilies<'a>,
    authority: CompletionAuthority<'a>,
) -> CompletionRoute {
    let transfers = matches!(
        result,
        FamilyCompletion::Suspended
            | FamilyCompletion::AccountedSuspended
            | FamilyCompletion::Switched(_)
            | FamilyCompletion::SwitchedWithWork(_)
            | FamilyCompletion::AccountedSwitched(_)
    );
    let authenticated = match authority {
        CompletionAuthority::Entry(token) if transfers => {
            carrick_core::entry::handoff(token);
            true
        }
        CompletionAuthority::BornInZone(token) if transfers => {
            carrick_core::entry::handoff_born_in_zone(token);
            true
        }
        CompletionAuthority::Entry(token) => pending
            .binding()
            .is_some_and(|live| carrick_core::entry::complete(token, live).is_ok()),
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
    match result {
        FamilyCompletion::AccountedComplete(_)
        | FamilyCompletion::AccountedSwitched(_)
        | FamilyCompletion::AccountedForward
        | FamilyCompletion::AccountedSuspended => {}
        FamilyCompletion::Forward | FamilyCompletion::Handback => pending.record_forwarded(ordinal),
        _ => pending.record_served(ordinal),
    }
    let route = completion_route(result, pending.host_work());
    if route == CompletionRoute::WithWork {
        pending.publish_work(matches!(result, FamilyCompletion::CommitOwed(_)));
    }
    route
}

/// One routing and completion owner. A retained IPC operation is offered to
/// its family before any fresh descriptor lookup, even with return work pending.
pub fn dispatch<'a>(
    ordinal: u64,
    control: u64,
    pending: &mut dyn PendingFamilies<'a>,
) -> CompletionRoute {
    let family = route_aarch64(ordinal, control);
    let completion = match pending.binding().and_then(|binding| {
        if let Some(token) = carrick_core::entry::admit(binding) {
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
            pending.record_forwarded(ordinal);
            return CompletionRoute::Forward;
        }
    };
    if matches!(family, Family::Anonymous(_))
        && let Some(result) = pending.prepare_anonymous()
    {
        return finish(ordinal, result, pending, completion);
    }
    let setup = pending.lifecycle_available()
        && matches!(family, Family::Lifecycle)
        && matches!(ordinal, 99 | 132 | 135);
    let transfer = pending.ipc_available()
        && matches!(family, Family::Read | Family::Write | Family::EpollWait);
    if pending.host_work() && !pending.resumes_operation() && !transfer && !setup {
        pending.declined_for_work(ordinal);
        return finish(ordinal, FamilyCompletion::Forward, pending, completion);
    }
    let mut result = serve_family(family, ordinal, pending);
    if result != FamilyCompletion::Forward {
        return finish(ordinal, result, pending, completion);
    }
    if pending.host_work() && !setup {
        pending.declined_for_work(ordinal);
        return finish(ordinal, result, pending, completion);
    }
    // File fallback follows the IPC authority's explicit decline, never a
    // retained operation's handback or completion.
    result = match family {
        Family::Read => pending.file_read(),
        Family::Write => pending.file_write(),
        _ => result,
    };
    finish(ordinal, result, pending, completion)
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
