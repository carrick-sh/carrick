//! Carrier-owned recall jobs. Requester cancellation never owns cleanup.
use super::*;
use crate::kernel::objects::{FileCursorReservation, FileDescriptionFdLease};
use crate::kernel::wait_set::WaitQueue;
use std::collections::VecDeque;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Once, OnceLock};

const READY: u32 = 1;
const RUNNING: u32 = 2;
const STORAGE_WORKERS: usize = 2;

struct DriverState {
    ready: VecDeque<Arc<RecallJob>>,
    // Routing only: the inode OwnerState is the sole strong cleanup owner.
    routes: [Weak<RecallJob>; MAX_DELEGATED_FILES],
    external_ready: bool,
}
struct Driver {
    state: Mutex<DriverState>,
    changed: parking_lot::Condvar,
}
static DRIVER: OnceLock<Driver> = OnceLock::new();
static START: Once = Once::new();
// Serializes the entire indexed drain, including stale/no-live-job candidates,
// with aperture retirement. No storage or guest-resource wait holds this gate.
static APERTURE_DRAIN: Mutex<()> = Mutex::new(());

pub(super) fn clear_aperture() {
    let _drain = APERTURE_DRAIN.lock();
    carrick_el1_abi::record_el1_region_host_ptr(0);
}

fn driver() -> &'static Driver {
    let driver = DRIVER.get_or_init(|| Driver {
        state: Mutex::new(DriverState {
            ready: VecDeque::with_capacity(MAX_DELEGATED_FILES),
            routes: std::array::from_fn(|_| Weak::new()),
            external_ready: false,
        }),
        changed: parking_lot::Condvar::new(),
    });
    START.call_once(|| {
        for index in 0..STORAGE_WORKERS {
            std::thread::Builder::new()
                .name(format!("carrick-recall-{index}"))
                .spawn(move || driver.run())
                .unwrap_or_else(|error| {
                    carrick_fatal!(
                        "el1_delegation",
                        "cannot start owned recall storage worker: {error}"
                    )
                });
        }
    });
    driver
}

/// A producer only nudges the carrier driver; it never performs storage or
/// acquires an owner/description guard in a completion callback.
pub(super) fn notify(_: &carrick_sched_core::ZoneTables, _: carrick_sched_core::Waker) {
    if let Some(driver) = DRIVER.get() {
        driver.state.lock().external_ready = true;
        driver.changed.notify_one();
    }
}
impl Driver {
    fn enqueue(&self, job: Arc<RecallJob>) {
        #[cfg(test)]
        if job.done.load(Ordering::Acquire) {
            TERMINAL_ENQUEUES.fetch_add(1, Ordering::Relaxed);
        }
        let mut state = self.state.lock();
        assert!(
            state.ready.len() < MAX_DELEGATED_FILES,
            "one queued recall per inode"
        );
        state.ready.push_back(job);
        self.changed.notify_one();
    }
    fn drain_external(&self) {
        let _drain = APERTURE_DRAIN.lock();
        let Some(zone) = zone_tables() else {
            return;
        };
        #[cfg(test)]
        if let Some(hook) = DRAIN_HOOK.lock().take() {
            hook();
        }
        for index in zone.take_delegated_host_pending() {
            // Pin the exact target before consuming any owed edge.
            let job = self.state.lock().routes[index.index()].upgrade();
            if let Some(job) = job {
                let phase = job.phase.lock();
                // Waiting custody pins the allocation. A completed job must
                // never dereference an aperture that teardown may now release.
                let owed = matches!(*phase, Phase::Waiting { .. })
                    && delegated_file_authority(
                        delegated_file_object(job.region, job.inode),
                        job.inode,
                    )
                    .take_host_recall_owed(job.generation);
                drop(phase);
                if owed {
                    job.schedule();
                }
            }
        }
    }
    fn run(&'static self) {
        loop {
            let mut state = self.state.lock();
            while state.ready.is_empty() && !state.external_ready {
                self.changed.wait(&mut state);
            }
            if state.external_ready {
                state.external_ready = false;
                drop(state);
                self.drain_external();
                continue;
            }
            let job = state.ready.pop_front();
            drop(state);
            if let Some(job) = job {
                job.run();
            }
        }
    }
}

enum Phase {
    Waiting {
        binding: Option<GuestBinding>,
        subscription: Option<HostRecallSubscription<'static>>,
    },
    Storage,
    Done,
}
pub(super) struct RecallJob {
    identity: InodeIdentity,
    region: usize,
    inode: u32,
    generation: NonZeroU64,
    phase: Mutex<Phase>,
    leases: Mutex<Vec<FileDescriptionFdLease>>,
    members: Vec<Arc<FileDescription>>,
    scheduling: AtomicU32,
    done: AtomicBool,
    completion: WaitQueue,
    retiring_member: Option<u32>,
    member_retired: AtomicBool,
    full_requested: AtomicBool,
}
impl RecallJob {
    pub(super) fn new(
        identity: InodeIdentity,
        binding: GuestBinding,
        retiring_member: Option<u32>,
    ) -> Arc<Self> {
        let region = get_el1_region_host_ptr();
        let inode = binding.inode;
        let generation = NonZeroU64::new(
            delegated_file_object(region, inode)
                .generation
                .load(Ordering::Acquire),
        )
        .unwrap_or_else(|| carrick_fatal!("el1_delegation", "live inode has no generation"));
        let members = binding.live_members();
        let leases = members
            .iter()
            .filter_map(FileDescription::retain_fd_lease)
            .collect();
        let job = Arc::new(Self {
            identity,
            region,
            inode,
            generation,
            phase: Mutex::new(Phase::Waiting {
                binding: Some(binding),
                subscription: None,
            }),
            leases: Mutex::new(leases),
            members,
            scheduling: AtomicU32::new(0),
            done: AtomicBool::new(false),
            completion: WaitQueue::new(),
            retiring_member,
            member_retired: AtomicBool::new(false),
            full_requested: AtomicBool::new(retiring_member.is_none()),
        });
        let index = inode as usize - 1;
        driver().state.lock().routes[index] = Arc::downgrade(&job);
        job
    }
    fn schedule(self: &Arc<Self>) {
        if self.done.load(Ordering::Acquire) {
            return;
        }
        if self.scheduling.fetch_or(READY, Ordering::AcqRel) & (READY | RUNNING) == 0 {
            if self.done.load(Ordering::Acquire) {
                self.scheduling.fetch_and(!READY, Ordering::AcqRel);
            } else {
                driver().enqueue(Arc::clone(self));
            }
        }
    }
    fn run(self: Arc<Self>) {
        self.scheduling.swap(RUNNING, Ordering::AcqRel);
        self.step();
        if self.done.load(Ordering::Acquire) {
            self.scheduling.store(0, Ordering::Release);
        } else if self.scheduling.fetch_and(!RUNNING, Ordering::AcqRel) & READY != 0 {
            driver().enqueue(Arc::clone(&self));
        }
        #[cfg(test)]
        if self.done.load(Ordering::Acquire) {
            let hook = {
                let mut hook = RUN_FINISHED_HOOK.lock();
                if hook
                    .as_ref()
                    .is_some_and(|(generation, _)| *generation == self.generation)
                {
                    hook.take().map(|(_, hook)| hook)
                } else {
                    None
                }
            };
            if let Some(hook) = hook {
                hook();
            }
        }
    }
    fn step(self: &Arc<Self>) {
        let mut phase = self.phase.lock();
        let Phase::Waiting {
            binding,
            subscription,
        } = &mut *phase
        else {
            return;
        };
        let file = delegated_file_object(self.region, self.inode);
        let authority = delegated_file_authority(file, self.inode);
        if subscription.is_none() {
            // SAFETY: this inode OwnerState strongly owns the job and its
            // binding, retaining allocation/base admission through terminal
            // withdrawal. Cancellation only drops requester result interest.
            *subscription = Some(
                unsafe { authority.subscribe_host_recall(self.generation) }.unwrap_or_else(|_| {
                    carrick_fatal!("el1_delegation", "lost owned inode recall admission")
                }),
            );
        }
        let Some(guard) = authority.try_host().unwrap_or_else(|_| {
            carrick_fatal!("el1_delegation", "lost owned inode recall generation")
        }) else {
            return;
        };
        drop(subscription.take());
        let binding = binding
            .take()
            .unwrap_or_else(|| unreachable!("waiting recall owns binding"));
        *phase = Phase::Storage;
        drop(phase);
        if let Some(member) = self.retiring_member
            && !self.full_requested.load(Ordering::Acquire)
            && !self.member_retired.swap(true, Ordering::AcqRel)
        {
            let mut binding = binding;
            fd_map_clear_handle(self.region, member);
            retire_open_file(self.region, member);
            for description in &self.members {
                if description.delegation_handle() == member {
                    description.set_delegation_handle(0);
                }
            }
            binding.members.retain(|entry| entry.open_file != member);
            drop(guard);
            let mut owners = OWNERS.lock();
            if self.full_requested.load(Ordering::Acquire) {
                *self.phase.lock() = Phase::Waiting {
                    binding: Some(binding),
                    subscription: None,
                };
                drop(owners);
                self.schedule();
                return;
            }
            let owner = owners
                .as_mut()
                .and_then(|map| map.get_mut(&self.identity))
                .unwrap_or_else(|| {
                    carrick_fatal!("el1_delegation", "member cleanup lost inode owner")
                });
            assert!(matches!(&owner.state, OwnerState::Recalling(job) if Arc::ptr_eq(job, self)));
            *self.phase.lock() = Phase::Done;
            owner.state = OwnerState::Guest(binding);
            self.done.store(true, Ordering::Release);
            OWNERS_CHANGED.notify_all();
            let leases = std::mem::take(&mut *self.leases.lock());
            drop(owners);
            self.completion.wake_all();
            drop(leases);
            return;
        }
        let live = execute_recall(self.identity, binding, guard);
        // Restore offsets and metadata without keeping a borrowed description
        // guard across host storage. No guest execution lease enters this pool.
        for member in &self.members {
            detach_recalled_member(member);
        }
        let mut retired_leases = Vec::new();
        loop {
            let leases = std::mem::take(&mut *self.leases.lock());
            for lease in &leases {
                detach_recalled_member(lease.description());
            }
            retired_leases.extend(leases);
            let mut owners = OWNERS.lock();
            if !self.leases.lock().is_empty() {
                drop(owners);
                continue;
            }
            if let Some(owner) = owners.as_mut().and_then(|map| map.get_mut(&self.identity)) {
                assert!(
                    matches!(&owner.state, OwnerState::Recalling(job) if Arc::ptr_eq(job, self))
                );
                *self.phase.lock() = Phase::Done;
                free_handle(self.inode);
                owner.state = OwnerState::Host;
            } else {
                carrick_fatal!("el1_delegation", "owned recall lost inode owner");
            }
            self.done.store(true, Ordering::Release);
            ACTIVE_DELEGATIONS.fetch_sub(1, Ordering::AcqRel);
            OWNERS_CHANGED.notify_all();
            drop(owners);
            break;
        }
        self.completion.wake_all();
        drop(retired_leases);
        drop(live);
    }
    pub(super) fn require_full(&self) {
        self.full_requested.store(true, Ordering::Release);
    }
    pub(super) fn wait(&self) {
        let mut owners = OWNERS.lock();
        while !self.done.load(Ordering::Acquire) {
            OWNERS_CHANGED.wait(&mut owners);
        }
    }
}

/// This is result interest only. The inode retains the job after cancellation.
pub struct OwnedRecallRequest {
    job: Option<Arc<RecallJob>>,
    cursor: FileCursorReservation,
    lease: FileDescriptionFdLease,
}

/// A completed recall paired with the exact continuously held cursor and
/// functional description. No caller can substitute a later reservation.
#[derive(Debug)]
pub struct OwnedRecallReady {
    cursor: FileCursorReservation,
    lease: FileDescriptionFdLease,
}
impl OwnedRecallReady {
    pub(crate) fn into_parts(self) -> (FileCursorReservation, FileDescriptionFdLease) {
        (self.cursor, self.lease)
    }
}
impl OwnedRecallRequest {
    pub fn is_complete(&self) -> bool {
        self.job
            .as_ref()
            .is_none_or(|job| job.done.load(Ordering::Acquire))
    }
    pub fn wait_queue(&self) -> Option<WaitQueue> {
        self.job.as_ref().map(|job| job.completion.clone())
    }
    /// Complete only the cursor admitted with this request. A pending result
    /// returns its entire owned state for the existing continuation to retain.
    pub fn try_ready(self) -> Result<OwnedRecallReady, Self> {
        if !self.is_complete() {
            return Err(self);
        }
        let Self {
            cursor,
            lease,
            job: _,
        } = self;
        Ok(OwnedRecallReady { cursor, lease })
    }
}
impl std::fmt::Debug for OwnedRecallRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedRecallRequest")
            .field("complete", &self.is_complete())
            .finish()
    }
}

/// The cursor reservation excludes the one initial delegation publication.
pub fn begin(cursor: FileCursorReservation) -> Result<OwnedRecallRequest, LinuxErrno> {
    let lease = cursor.description().retain_fd_lease().ok_or(LINUX_EBADF)?;
    let job = handoff(lease.clone(), true);
    Ok(OwnedRecallRequest { job, cursor, lease })
}

/// Called only after lifecycle admission retained the last functional reference.
pub(crate) fn handoff(lease: FileDescriptionFdLease, full: bool) -> Option<Arc<RecallJob>> {
    let description = lease.description();
    if description.delegation_handle() == 0 {
        return None;
    }
    let identity = description.el1_identity().unwrap_or_else(|| {
        carrick_fatal!("el1_delegation", "delegated last reference has no identity")
    });
    let mut owners = OWNERS.lock();
    let owner = owners
        .as_mut()
        .and_then(|map| map.get_mut(&identity))
        .unwrap_or_else(|| carrick_fatal!("el1_delegation", "delegated last reference lost owner"));
    let job = match &owner.state {
        OwnerState::Recalling(job) => {
            if full {
                job.require_full();
            }
            Arc::clone(job)
        }
        OwnerState::Guest(_) => {
            let OwnerState::Guest(binding) = std::mem::replace(&mut owner.state, OwnerState::Host)
            else {
                unreachable!()
            };
            let retiring_member = (!full
                && binding.members.len() > 1
                && binding
                    .members
                    .iter()
                    .any(|member| member.open_file == description.delegation_handle()))
            .then_some(description.delegation_handle());
            let job = RecallJob::new(identity, binding, retiring_member);
            owner.state = OwnerState::Recalling(Arc::clone(&job));
            job
        }
        OwnerState::Host => {
            // A pending join has no offset record. Existing actual members were
            // detached before the terminal owner publication.
            assert!(matches!(description.delegation_handle(), 0 | JOIN_PENDING));
            description.set_delegation_handle(0);
            drop(owners);
            return None;
        }
        OwnerState::Delegating { .. } => {
            carrick_fatal!(
                "el1_delegation",
                "cursor/last-reference admission crossed initial publication"
            )
        }
    };
    job.leases.lock().push(lease);
    drop(owners);
    job.schedule();
    Some(job)
}

/// The synchronous legacy entry joins the same owned job, never a second recall.
pub(super) fn elect(identity: InodeIdentity, binding: GuestBinding) -> Arc<RecallJob> {
    RecallJob::new(identity, binding, None)
}
pub(super) fn start(job: &Arc<RecallJob>) {
    job.schedule();
}

#[cfg(test)]
pub(super) fn wait_for_cleanup(identity: InodeIdentity) {
    let owners = OWNERS.lock();
    let job = owners
        .as_ref()
        .and_then(|map| map.get(&identity))
        .and_then(|owner| match &owner.state {
            OwnerState::Recalling(job) => Some(Arc::clone(job)),
            _ => None,
        });
    drop(owners);
    if let Some(job) = job {
        job.wait();
    }
}

#[cfg(test)]
pub(super) static DRAIN_HOOK: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);
#[cfg(test)]
pub(super) fn test_drain_external() {
    driver().drain_external();
}
#[cfg(test)]
pub(super) fn completed_schedule_is_ignored(request: &OwnedRecallRequest) -> bool {
    let job = request.job.as_ref().expect("test started an actual recall");
    job.wait();
    let before = job.scheduling.load(Ordering::Acquire);
    job.schedule();
    let after = job.scheduling.load(Ordering::Acquire);
    // RUNNING can retire concurrently; a terminal request must never add READY.
    after & READY == 0 && (before & READY == 0)
}

#[cfg(test)]
pub(super) static TERMINAL_ENQUEUES: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
type RunFinishedHook = (NonZeroU64, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static RUN_FINISHED_HOOK: Mutex<Option<RunFinishedHook>> = Mutex::new(None);
#[cfg(test)]
pub(super) fn requeue_while_running(request: &OwnedRecallRequest) -> Box<dyn FnOnce() + Send> {
    let job = Arc::clone(request.job.as_ref().expect("actual recall"));
    Box::new(move || job.schedule())
}
#[cfg(test)]
pub(super) fn observe_run_finished(request: &OwnedRecallRequest) -> std::sync::mpsc::Receiver<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let generation = request.job.as_ref().expect("actual recall").generation;
    *RUN_FINISHED_HOOK.lock() = Some((
        generation,
        Box::new(move || {
            let _ = tx.send(());
        }),
    ));
    rx
}
