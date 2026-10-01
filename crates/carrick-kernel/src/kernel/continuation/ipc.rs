//! Host completion of pipe/eventfd operations EL1 owns in the shared IPC
//! authority (`carrick_el1_abi::ipc`): the operations EL1 handed back
//! ([`carrick_el1_abi::ipc::IPC_HANDBACK_NR`]) and the parked ones the host
//! claimed (a signal, an exit or exec drain, a control action).
//!
//! One owner completes each operation exactly once: the owned
//! [`IpcOpToken`] is consumed by [`finish`] (which retires the record, drops
//! the description pin and performs a final release) or handed on as
//! [`IpcHostOutcome::Blocked`]. Progress is never replayed: a resumed
//! continuation starts from `progress.written`, and an interruption after
//! progress returns the count.
//!
//! Interruption policy (signal(7), pipe(7)): with progress, return the byte
//! count (SIGPIPE still delivered for a broken pipe); without progress, a
//! handler with `SA_RESTART` restarts the call (it had no effect), otherwise
//! EINTR. A control action (stop, exec/exit drain) restarts a zero-progress
//! call and returns the count otherwise.

use carrick_abi::{LINUX_EFAULT, LINUX_EINTR, LINUX_EINVAL, LINUX_EPIPE, LinuxErrno};
use carrick_el1::substrate::file::UserCopy;
use carrick_el1::substrate::ipc::{PrefixCopy, StepStatus, transfer};
pub use carrick_el1::substrate::ipc::{from_sched_token, to_sched_token, wait_key};
use carrick_el1_abi::ipc::pipe::WaitFor;
#[cfg(test)]
use carrick_el1_abi::ipc::pipe::WakeSet;
use carrick_el1_abi::ipc::{
    IpcError, IpcHandback, IpcMmKey, IpcObjectHandle, IpcOpKind, IpcOpToken, IpcOperation,
    IpcRegion, IpcReleased, IpcWake, OfdPin, RawIpcOpToken,
};
pub use carrick_sched_core::object_wait::{ObjectWaitError, ObjectWaitSnapshot};

/// The host waits for the short sections other parties hold object and
/// descriptor-table locks for (the zone's host lock policy).
pub use crate::el1_zone::HostLockWait as HostIpcWait;

/// Host services for one completion owner: authenticate its mapping, retire
/// host tokens, and deliver object wakes. Callbacks run with no IPC lock held.
pub trait IpcHostServices {
    fn validate_region(&self, region: &IpcRegion<'_>) -> Result<(), IpcError>;
    fn release_host(&self, token: carrick_el1_abi::ipc::HostResourceToken) -> Result<(), IpcError>;
    /// Deliver a published change after every IPC lock is released: the
    /// object's guest waiters on the advanced lanes, and its host
    /// subscribers when the publication owed them (`host_owed`).
    fn wake(&self, wake: IpcWake);
    /// The guest virtual counter now (an epoll wait's deadline is on it).
    fn counter(&self) -> CounterClock {
        CounterClock::host()
    }
}

/// A reading of the guest virtual counter (`CNTVCT_EL0`) with its tick
/// scale. On the host the counter is the host's monotonic tick (no offset),
/// the same reading EL1 takes deadlines on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterClock {
    /// Counter value now.
    pub now: u64,
    /// Nanoseconds per tick, as `numer / denom`.
    pub numer: u64,
    pub denom: u64,
}

impl CounterClock {
    pub fn host() -> Self {
        let scale = carrick_host::clock::tick_scale()
            .unwrap_or(carrick_host::clock::TickScale { numer: 1, denom: 1 });
        Self {
            now: carrick_host::clock::monotonic_ticks(),
            numer: u64::from(scale.numer),
            denom: u64::from(scale.denom.max(1)),
        }
    }

    /// Whole milliseconds left until `deadline`, rounded up so a re-run
    /// never ends before it; 0 once it has passed.
    pub fn remaining_ms(self, deadline: u64) -> i32 {
        let ticks = deadline.saturating_sub(self.now);
        let ns = u128::from(ticks) * u128::from(self.numer) / u128::from(self.denom.max(1));
        i32::try_from(ns.div_ceil(1_000_000)).unwrap_or(i32::MAX)
    }
}

/// The production completion owner and scheduler's host placement for object
/// queues (`notify_object_host`), never impersonating a running guest slot.
/// Placed waiters run in the guest (their slot rescheduled when owed);
/// waiters no slot admits are handed to their host continuations.
pub struct ZoneHostServices {
    owner: std::sync::Arc<crate::el1_ipc::HostIpc>,
}

impl ZoneHostServices {
    pub fn new(kernel: &crate::kernel::Kernel) -> Result<Self, IpcError> {
        Ok(Self {
            owner: kernel.existing_ipc().ok_or(IpcError::Stale)?,
        })
    }

    /// Completion may retire a cancelled task whose context no longer resolves.
    /// The dispatcher still retains its kernel's resource owner.
    pub fn for_dispatcher(
        dispatcher: &crate::dispatch::SyscallDispatcher,
    ) -> Result<Self, IpcError> {
        Self::new(dispatcher.kernel_binding.read().kernel())
    }
}

impl IpcHostServices for ZoneHostServices {
    fn validate_region(&self, region: &IpcRegion<'_>) -> Result<(), IpcError> {
        if region.same_mapping(&self.owner.region()) {
            Ok(())
        } else {
            Err(IpcError::BadRegion)
        }
    }
    fn release_host(&self, token: carrick_el1_abi::ipc::HostResourceToken) -> Result<(), IpcError> {
        self.owner
            .release(carrick_el1_abi::ipc::IpcBacking::Host(token).encode())
            .map(|_| ())
    }
    fn wake(&self, wake: IpcWake) {
        // The owed host wake goes through the same owner delivery as a
        // host-side pipe/eventfd change (`service_host_wake`).
        self.owner.service_wake(&wake);
        let Some(zone) = crate::el1_zone::zone() else {
            return;
        };
        // The object's own lanes, then each zone epoll it queued items on.
        let lanes = [
            (wake.object, WaitFor::Readable, wake.readers),
            (wake.object, WaitFor::Writable, wake.writers),
        ]
        .into_iter()
        .chain(
            wake.epolls
                .iter()
                .map(|epoll| (epoll, WaitFor::Readable, true)),
        );
        for (object, lane, due) in lanes {
            let Some(key) = due.then(|| wait_key(object, lane)).flatten() else {
                continue;
            };
            let mut handed = Vec::new();
            let mut placed = Vec::new();
            {
                // A queue never bound to this incarnation has no waiters.
                let Ok(guard) = zone.object_wait(key, &HostIpcWait) else {
                    continue;
                };
                let _ = guard
                    .notify_object_host(&mut |record| handed.push(record), &mut |placement| {
                        placed.push(placement)
                    });
            }
            for placement in placed {
                if placement.resched {
                    crate::el1_zone::resched_slot(placement.slot);
                }
            }
            crate::el1_zone::hand_back(&handed);
        }
    }
}

/// The host IPC authority's memory for the carrier to map into the IPC
/// window, or `None` while the kernel has no authority (every IPC path then
/// stays closed: nothing is mapped, EL1 never attaches, no table is
/// published).
///
/// Bridge to the host authority's owner (checkpoint-3 T4, `Kernel::ipc()`
/// / `HostIpc`): it returns that authority adapted to
/// [`carrick_el1_abi::IpcWindowBacking`]. The runtime registers the result
/// with the carrier before its first persistent root.
pub fn host_window_backing(
    dispatcher: &crate::dispatch::SyscallDispatcher,
) -> Option<std::sync::Arc<dyn carrick_el1_abi::IpcWindowBacking>> {
    let owner = dispatcher.kernel_binding.read().kernel().ipc().ok()?;
    Some(owner)
}

/// Bind the current production file table before returning to the guest.
/// Missing windows and bounded admission refusals retain host service. Never
/// publish a different kernel's descriptor IDs into the carrier's mapping.
pub fn publish_file_table(context: &crate::kernel::KernelContext) {
    let Some(map) = carrick_el1_abi::ipc_table_map_host() else {
        return;
    };
    if !map.window_published() {
        return;
    }
    let Some(region) = host_region() else {
        return;
    };
    let Some(owner) = context.kernel().existing_ipc() else {
        return;
    };
    if !region.same_mapping(&owner.region()) {
        return;
    }
    let _ = context.resources().files().publish_ipc(owner, map);
}

/// Deliver guest-produced IPC readiness at this kernel's host boundary.
/// Kernel identity is explicit: no process-global callback can select another
/// container's authority or silently leave this kernel's subscribers asleep.
pub fn deliver_owed_host_wakes(kernel: &crate::kernel::Kernel) {
    kernel.deliver_ipc_host_wakes();
}

/// The host's view of the shared IPC authority, once the carrier mapped
/// its window and the authority published its directory; `None` otherwise
/// (every IPC path then stays closed).
pub fn host_region() -> Option<IpcRegion<'static>> {
    carrick_el1_abi::ipc_window_host()?.attach().ok()
}

/// The wait-queue snapshots of both lanes of `object`, taken BEFORE its
/// readiness is checked under the object lock (binding each queue to this
/// incarnation on first use), so a park after a failed check can never miss
/// a notification in between.
pub fn lane_snapshots(
    zone: &carrick_el1_abi::ZoneTables,
    object: IpcObjectHandle,
) -> [Option<ObjectWaitSnapshot>; 2] {
    [WaitFor::Readable, WaitFor::Writable].map(|lane| {
        let key = wait_key(object, lane)?;
        let _ = zone.bind_object_wait(key, &HostIpcWait);
        zone.object_wait(key, &HostIpcWait)
            .ok()
            .map(|guard| guard.snapshot())
    })
}

/// Why a parked or handed-back operation stops before completing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcCause {
    /// A signal whose handler will run; `restart` is its `SA_RESTART`.
    Signal { restart: bool },
    /// A job-control stop (a default-action stop signal), after which the
    /// thread continues on `SIGCONT` with no handler run.
    Stop,
    /// A control action that never returns to the guest (exec, exit or
    /// group-exit drain) or one Linux does not count as an interruption (a
    /// quiesce, an ignored signal).
    Control,
    /// The park's deadline passed while the host kept it (only an
    /// [`IpcOpKind::EpollWait`] parks with one).
    Timeout,
}

/// What the host does with the thread after completing its operation.
#[derive(Debug, Eq, PartialEq)]
pub enum IpcHostOutcome {
    /// Return `result` after the SVC; `sigpipe` requests SIGPIPE too.
    Complete { result: i64, sigpipe: bool },
    /// No effect was taken: resume at the SVC with the original `x0` and
    /// syscall number (the call runs again). `timeout_ms`: a timed epoll
    /// wait re-runs with what is left of its deadline as its timeout
    /// argument (`x3`), never the full original timeout; 0 once it passed
    /// (one more harvest, then 0 events).
    Restart {
        x0: u64,
        nr: u32,
        timeout_ms: Option<i32>,
    },
    /// Still waiting on `lane`: park the thread with `token` (resumption at
    /// the SVC; EL1 or the host takes the token before any fd lookup).
    Blocked {
        token: IpcOpToken,
        object: IpcObjectHandle,
        lane: WaitFor,
        x0: u64,
        nr: u32,
    },
}

/// The owned operation a handback frame names (its packed token in `x0`).
pub fn take_handback(
    region: &IpcRegion<'_>,
    x0: u64,
) -> Result<(IpcOpToken, IpcOperation), IpcError> {
    let token = IpcOpToken::from_raw(RawIpcOpToken::unpack(x0));
    let op = region.operation(&token)?;
    Ok((token, op))
}

/// Re-run a parked epoll wait with what is left of its wait.
fn epoll_rerun(op: &IpcOperation, clock: CounterClock) -> IpcHostOutcome {
    IpcHostOutcome::Restart {
        x0: op.orig_x0,
        nr: op.nr,
        timeout_ms: op
            .deadline
            .get()
            .map(|deadline| clock.remaining_ms(deadline)),
    }
}

/// The outcome of stopping `op` for `cause` at counter reading `clock`
/// (pure policy).
pub fn interrupted(op: &IpcOperation, cause: IpcCause, clock: CounterClock) -> IpcHostOutcome {
    if op.kind == IpcOpKind::EpollWait {
        // epoll_wait(2) is never restarted after a handler, SA_RESTART or
        // not, and a stop followed by SIGCONT interrupts it too, with no
        // handler (man 7 signal, the Linux-specific list). Other control
        // actions re-run it with what is left of its deadline (no event was
        // taken).
        return match cause {
            IpcCause::Signal { .. } | IpcCause::Stop => IpcHostOutcome::Complete {
                result: LINUX_EINTR.guest_retval(),
                sigpipe: false,
            },
            IpcCause::Control => epoll_rerun(op, clock),
            // The timeout elapsed with nothing reported.
            IpcCause::Timeout => IpcHostOutcome::Complete {
                result: 0,
                sigpipe: false,
            },
        };
    }
    let written = op.progress.written;
    if written > 0 {
        return IpcHostOutcome::Complete {
            result: written as i64,
            sigpipe: false,
        };
    }
    match cause {
        IpcCause::Signal { restart: false } => IpcHostOutcome::Complete {
            result: LINUX_EINTR.guest_retval(),
            sigpipe: false,
        },
        // A read/write never parks with a deadline: a timeout claim is a
        // control action for it. A stop is not in man 7 signal's list for
        // read/write: after SIGCONT the call continues (here: re-runs).
        IpcCause::Signal { restart: true }
        | IpcCause::Stop
        | IpcCause::Control
        | IpcCause::Timeout => IpcHostOutcome::Restart {
            x0: op.orig_x0,
            nr: op.nr,
            timeout_ms: None,
        },
    }
}

/// Retire the operation (consuming its token), drop its description pin and
/// perform a final release, waking the peer lanes. Exactly once: a second
/// finish of the same token is `Stale`.
pub fn finish(
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    wake: &impl IpcHostServices,
) -> Result<IpcOperation, IpcError> {
    wake.validate_region(region)?;
    let op = region.finish_operation(token)?;
    if op.pin.authority != 0 {
        let fd = region.fd(HostIpcWait);
        if let Some(description) = fd.unpin(OfdPin::from_raw(op.pin)).map_err(IpcError::Fd)? {
            match region.release_backing(description.backing, &HostIpcWait)? {
                IpcReleased::Object {
                    wake: w,
                    freed: false,
                } => wake.wake(w),
                IpcReleased::Host(token) => wake.release_host(token)?,
                IpcReleased::Object { freed: true, .. } | IpcReleased::Epoll => {}
            }
        }
    }
    Ok(op)
}

/// Stop a parked or handed-back operation for `cause` and finish it.
pub fn interrupt(
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    cause: IpcCause,
    wake: &impl IpcHostServices,
) -> Result<IpcHostOutcome, IpcError> {
    let op = finish(region, token, wake)?;
    Ok(interrupted(&op, cause, wake.counter()))
}

/// Most bytes one host step can move (the largest pipe capacity).
const HOST_STEP_BYTES: u64 = 1 << 20;

/// The host's user copies for one step. Touching guest memory may fault
/// pages in and pause the address space, which must never happen under an
/// IPC lock: copies in are served from a prefix read before the lock, and
/// copies out are validated under it and landed after it.
struct HostCopy<'m, M: carrick_guest_mem::CurrentMmMemory> {
    memory: &'m mut M,
    prefetch_va: u64,
    prefetch: Vec<u8>,
    pending: Vec<(u64, Vec<u8>)>,
}

impl<M: carrick_guest_mem::CurrentMmMemory> UserCopy for HostCopy<'_, M> {
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
        if !self.memory.guest_range_is_writable(dst_va, src.len()) {
            return false;
        }
        self.pending.push((dst_va, src.to_vec()));
        true
    }

    fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
        let Some(start) = src_va
            .checked_sub(self.prefetch_va)
            .and_then(|o| usize::try_from(o).ok())
        else {
            return false;
        };
        let Some(bytes) = start
            .checked_add(dst.len())
            .and_then(|end| self.prefetch.get(start..end))
        else {
            return false;
        };
        dst.copy_from_slice(bytes);
        true
    }
}

impl<M: carrick_guest_mem::CurrentMmMemory> HostCopy<'_, M> {
    /// Read the longest readable prefix of `[va, va+len)` before any lock.
    fn prefetch(&mut self, va: u64, len: u64) {
        self.prefetch_va = va;
        self.prefetch.clear();
        let mut at = 0u64;
        while at < len {
            let n = (len - at).min(4096 - (va + at) % 4096);
            match self.memory.read_bytes(va + at, n as usize) {
                Ok(bytes) => self.prefetch.extend_from_slice(&bytes),
                Err(_) => break,
            }
            at += n;
        }
    }

    fn land(&mut self) -> bool {
        let mut landed = true;
        for (va, bytes) in self.pending.drain(..) {
            landed &= self.memory.write_bytes(va, &bytes).is_ok();
        }
        landed
    }
}

fn errno(e: LinuxErrno) -> i64 {
    e.guest_retval()
}

/// Complete an operation EL1 handed back, on the calling thread's own
/// memory (`mm` is the address space the host installed for it: an
/// operation of another address space is refused before any copy).
/// `signal` is a deliverable signal (or control action) pending for the
/// thread: a continuation stops for it instead of taking more effects.
pub fn complete_handback<M: carrick_guest_mem::CurrentMmMemory>(
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    mm: IpcMmKey,
    memory: &mut M,
    signal: Option<IpcCause>,
    wake: &impl IpcHostServices,
) -> Result<IpcHostOutcome, IpcError> {
    wake.validate_region(region)?;
    let mut op = region.operation(&token)?;
    match op.handback {
        IpcHandback::Sigpipe => {
            let op = finish(region, token, wake)?;
            return Ok(IpcHostOutcome::Complete {
                result: op.result,
                sigpipe: true,
            });
        }
        IpcHandback::Restart => {
            let op = finish(region, token, wake)?;
            return Ok(IpcHostOutcome::Restart {
                x0: op.orig_x0,
                nr: op.nr,
                timeout_ms: None,
            });
        }
        IpcHandback::Continue => {}
        IpcHandback::None => return Err(IpcError::Corrupt),
    }
    if op.mm != mm {
        // A stale or foreign address space never receives these bytes.
        return Err(IpcError::Stale);
    }
    if let Some(cause) = signal {
        return interrupt(region, token, cause, wake);
    }
    if op.kind == IpcOpKind::EpollWait {
        // A parked zone epoll wait owns no progress: the host runs the
        // original call (its harvest covers both halves) with what is left
        // of its deadline, so a wake that found nothing never extends it.
        let clock = wake.counter();
        let op = finish(region, token, wake)?;
        return Ok(epoll_rerun(&op, clock));
    }
    let object = IpcObjectHandle::from_raw(op.object);
    let nonblock = {
        let pin = OfdPin::from_raw(op.pin);
        let flags = region
            .fd(HostIpcWait)
            .pinned(&pin)
            .map(|d| d.flags.nonblock);
        op.pin = pin.into_raw();
        flags.map_err(IpcError::Fd)?
    };
    let mut user = HostCopy {
        memory,
        prefetch_va: 0,
        prefetch: Vec::new(),
        pending: Vec::new(),
    };
    if op.kind == IpcOpKind::PipeWrite {
        let va = op.buf.0.wrapping_add(op.progress.written);
        user.prefetch(va, (op.progress.remaining() as u64).min(HOST_STEP_BYTES));
    }
    let (status, published) = {
        let mut guard = region.lock(object, &HostIpcWait)?;
        let mut copy = PrefixCopy::new(&mut user);
        let (status, wake_set) = transfer(&mut guard, &mut op, &mut copy)?;
        (status, guard.publish(wake_set))
    };
    let landed = user.land();
    region.update_operation(&token, op)?;
    if published.readers || published.writers {
        wake.wake(published);
    }
    let written = op.progress.written as i64;
    let outcome = |result: i64| IpcHostOutcome::Complete {
        result,
        sigpipe: false,
    };
    let result = match status {
        _ if !landed => {
            // A destination unmapped since validation: EFAULT, as a
            // concurrent unmap mid-copy is on Linux.
            finish(region, token, wake)?;
            return Ok(outcome(errno(LINUX_EFAULT)));
        }
        StepStatus::Complete => written,
        StepStatus::EndOfFile => 0,
        StepStatus::Invalid => errno(LINUX_EINVAL),
        StepStatus::Blocked(_) if nonblock => {
            if written > 0 {
                written
            } else {
                errno(carrick_abi::LINUX_EAGAIN)
            }
        }
        StepStatus::Blocked(lane) => {
            return Ok(IpcHostOutcome::Blocked {
                token,
                object,
                lane,
                x0: op.orig_x0,
                nr: op.nr,
            });
        }
        StepStatus::Broken => {
            finish(region, token, wake)?;
            return Ok(IpcHostOutcome::Complete {
                result: if written > 0 {
                    written
                } else {
                    errno(LINUX_EPIPE)
                },
                sigpipe: true,
            });
        }
        StepStatus::Fault if written > 0 && op.kind == IpcOpKind::PipeRead => written,
        StepStatus::Fault if written > 0 => written,
        StepStatus::Fault => errno(LINUX_EFAULT),
    };
    finish(region, token, wake)?;
    Ok(outcome(result))
}

#[cfg(test)]
mod tests;
