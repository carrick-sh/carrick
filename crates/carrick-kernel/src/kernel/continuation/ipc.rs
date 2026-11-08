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
    /// Publish a returned operation slot through the exact carrier owner.
    fn operation_slot_released(&self, region: &IpcRegion<'_>);
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
    fn operation_slot_released(&self, region: &IpcRegion<'_>) {
        if let Some(zone) = crate::el1_zone::zone() {
            zone.notify_ipc_operation_slot_release(
                region.operation_slot_generation(),
                carrick_sched_core::Waker::Host,
                &|owned| crate::el1_zone::complete_object_wake(zone, owned),
            );
        }
    }
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
                let Ok(guard) = zone.object_wait(key, &HostIpcWait, &|owned| {
                    crate::el1_zone::complete_object_wake(owned.zone(), owned)
                }) else {
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
        let _ = zone.bind_object_wait(key, &HostIpcWait, &|owned| {
            crate::el1_zone::complete_object_wake(owned.zone(), owned)
        });
        zone.object_wait(key, &HostIpcWait, &|owned| {
            crate::el1_zone::complete_object_wake(owned.zone(), owned)
        })
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
    /// The park's absolute counter deadline passed while the host kept it.
    Timeout,
}

/// What the host does with the thread after completing its operation.
#[derive(Debug, Eq, PartialEq)]
pub enum IpcHostOutcome {
    /// Return `result` after the SVC; `sigpipe` requests SIGPIPE too.
    Complete { result: i64, sigpipe: bool },
    /// Re-enter a syscall under its own register convention.
    Restart(IpcRestart),
    /// The output was refused before consuming anything. Keep the operation
    /// and its endpoint pin while the existing owner-memory machinery waits.
    OwnerMemory {
        token: IpcOpToken,
        outcome: Box<crate::dispatch::DispatchOutcome>,
    },
    /// Still waiting on `lane`: park the thread with `token` (resumption at
    /// the SVC; EL1 or the host takes the token before any fd lookup).
    Blocked {
        token: IpcOpToken,
        object: IpcObjectHandle,
        lane: WaitFor,
        deadline: Option<u64>,
        x0: u64,
        nr: u32,
    },
}

/// Register conventions for zero-progress syscall re-entry. A timed
/// pointer argument cannot be paired with epoll's millisecond rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcRestart {
    Original { x0: u64, nr: u32 },
    EpollPwait { x0: u64, timeout_ms: i32 },
}

impl IpcHostOutcome {
    /// The only argument rewrite a host completion authorizes. The syscall
    /// ordinal travels with the convention, never with an arbitrary caller.
    pub fn replay_argument(&self) -> Option<(carrick_abi::CanonicalNr, usize, u64)> {
        match self {
            Self::Restart(IpcRestart::EpollPwait { timeout_ms, .. }) => Some((
                carrick_abi::syscall::nr::EPOLL_PWAIT,
                3,
                *timeout_ms as u32 as u64,
            )),
            _ => None,
        }
    }
}

/// An operation retained across an owner-memory wait. Cancellation releases
/// the exact endpoint pin once; resumption never looks the numeric fd up again.
pub struct RetainedIpcOperation {
    token: Option<IpcOpToken>,
    service: ZoneHostServices,
}

impl RetainedIpcOperation {
    pub fn new(kernel: &crate::kernel::Kernel, token: IpcOpToken) -> Result<Self, IpcError> {
        let service = ZoneHostServices::new(kernel)?;
        service.owner.region().operation(&token)?;
        Ok(Self {
            token: Some(token),
            service,
        })
    }

    pub fn object(&self) -> Result<IpcObjectHandle, IpcError> {
        let token = self.token.as_ref().ok_or(IpcError::Stale)?;
        Ok(IpcObjectHandle::from_raw(
            self.service.owner.region().operation(token)?.object,
        ))
    }

    pub fn resume<M: carrick_guest_mem::CurrentMmMemory>(
        mut self,
        context: &crate::kernel::KernelContext,
        mm: IpcMmKey,
        memory: &mut M,
    ) -> Result<IpcHostOutcome, IpcError> {
        let token = self.token.take().ok_or(IpcError::Stale)?;
        let raw = token.into_raw();
        let outcome = complete_handback(
            context,
            &self.service.owner.region(),
            IpcOpToken::from_raw(raw),
            mm,
            memory,
            None,
            &self.service,
        );
        if outcome.is_err() {
            self.token = Some(IpcOpToken::from_raw(raw));
        }
        outcome
    }
}

impl Drop for RetainedIpcOperation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = finish(&self.service.owner.region(), token, &self.service);
        }
    }
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
    IpcHostOutcome::Restart(IpcRestart::EpollPwait {
        x0: op.orig_x0,
        timeout_ms: op
            .deadline
            .get()
            .map_or(-1, |deadline| clock.remaining_ms(deadline)),
    })
}

/// The outcome of stopping `op` for `cause` at counter reading `clock`
/// (pure policy).
pub(crate) fn interrupted(
    op: &IpcOperation,
    cause: IpcCause,
    clock: CounterClock,
) -> IpcHostOutcome {
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
    use carrick_signal_core::wait::{
        RestartClass, TransferredBytes, WaitDecision, WaitProgress, interrupted_wait,
    };
    let progress = usize::try_from(op.progress.written)
        .ok()
        .and_then(TransferredBytes::new)
        .map_or(WaitProgress::Blocked, WaitProgress::Transferred);
    let restart = match cause {
        IpcCause::Signal { restart } => Some(restart),
        IpcCause::Stop | IpcCause::Control | IpcCause::Timeout => None,
    };
    match interrupted_wait(RestartClass::IfSaRestart, progress, restart) {
        WaitDecision::CompletePartial(bytes) => IpcHostOutcome::Complete {
            result: bytes.get() as i64,
            sigpipe: false,
        },
        WaitDecision::Eintr => IpcHostOutcome::Complete {
            result: LINUX_EINTR.guest_retval(),
            sigpipe: false,
        },
        _ => IpcHostOutcome::Restart(IpcRestart::Original {
            x0: op.orig_x0,
            nr: op.nr,
        }),
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
    let op = region.finish_operation(token, || wake.operation_slot_released(region))?;
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

/// Settle a parked or handed-back operation for `cause`. Control actions
/// retain PollWait's admission; handler interruptions finish it with EINTR.
pub fn interrupt<M: carrick_guest_mem::CurrentMmMemory>(
    context: &crate::kernel::KernelContext,
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    mm: IpcMmKey,
    memory: &mut M,
    cause: IpcCause,
    wake: &impl IpcHostServices,
) -> Result<IpcHostOutcome, IpcError> {
    wake.validate_region(region)?;
    let mut op = region.operation(&token)?;
    if op.mm != mm {
        return Err(IpcError::Stale);
    }
    if op.kind == IpcOpKind::PollWait {
        // A directly claimed ring park may still have handback=None. Once
        // the host owns completion, a copyout refusal must be resumable by
        // complete_handback without losing its decided answer or token.
        op.handback = IpcHandback::Continue;
        region.update_operation(&token, op)?;
        return complete_poll(context, region, token, op, memory, Some(cause), wake);
    }
    let op = finish(region, token, wake)?;
    Ok(interrupted(&op, cause, wake.counter()))
}

/// Complete the admitted single-description poll. Readiness uses the shared
/// IPC member-level primitive, never a numeric-fd lookup or a new relative
/// timeout. Once decided, the answer and byte cursor stay in the same arena
/// record through owner-copyout refusals.
fn complete_poll<M: carrick_guest_mem::CurrentMmMemory>(
    context: &crate::kernel::KernelContext,
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    mut op: IpcOperation,
    memory: &mut M,
    cause: Option<IpcCause>,
    wake: &impl IpcHostServices,
) -> Result<IpcHostOutcome, IpcError> {
    use crate::dispatch::copyout::{self, UserSlot};
    use carrick_el1_abi::ipc::{IpcBacking, WriteProgress, epoll::EpollMember};
    let complete = |result| IpcHostOutcome::Complete {
        result,
        sigpipe: false,
    };
    if op.progress.len == 0 {
        if matches!(cause, Some(IpcCause::Signal { .. } | IpcCause::Stop)) {
            finish(region, token, wake)?;
            return Ok(complete(LINUX_EINTR.guest_retval()));
        }
        let pin = OfdPin::from_raw(op.pin);
        let description = region.fd(HostIpcWait).pinned(&pin);
        op.pin = pin.into_raw();
        let (object, member) = description.map_err(IpcError::Fd).and_then(|d| {
            IpcBacking::decode(d.backing)
                .and_then(EpollMember::of_backing)
                .ok_or(IpcError::Corrupt)
        })?;
        if object.to_raw() != op.object {
            return Err(IpcError::Corrupt);
        }
        let mut bytes = op.value.0.to_ne_bytes();
        let events = i16::from_ne_bytes([bytes[4], bytes[5]]);
        let mut guard = region.lock(object, &HostIpcWait)?;
        let level = guard.member_level(member)?;
        drop(guard);
        let revents =
            level as i16 & (events | carrick_abi::LINUX_POLLERR | carrick_abi::LINUX_POLLHUP);
        if revents == 0 && op.deadline.get().is_none_or(|end| wake.counter().now < end) {
            let lane = match member {
                EpollMember::PipeWriter => WaitFor::Writable,
                EpollMember::EventFd
                    if events as u16 as u32 & carrick_el1_abi::ipc::epoll::events::WRITE_SIDE
                        != 0 =>
                {
                    WaitFor::Writable
                }
                _ => WaitFor::Readable,
            };
            return Ok(IpcHostOutcome::Blocked {
                token,
                object,
                lane,
                deadline: op.deadline.get(),
                x0: op.orig_x0,
                nr: op.nr,
            });
        }
        bytes[6..].copy_from_slice(&revents.to_ne_bytes());
        op.value = carrick_el1_abi::ipc::IpcEventValue(u64::from_ne_bytes(bytes));
        op.result = i64::from(revents != 0);
        op.progress = WriteProgress::new(8);
        region.update_operation(&token, op)?;
    }
    let bytes = op.value.0.to_ne_bytes();
    while !op.progress.is_complete() {
        let offset = op.progress.written as usize;
        let address = op
            .buf
            .0
            .checked_add(op.progress.written)
            .ok_or(IpcError::Corrupt)?;
        let length = (8 - offset).min(
            (carrick_el1::substrate::ipc::USER_COPY_GRANULE
                - address % carrick_el1::substrate::ipc::USER_COPY_GRANULE) as usize,
        );
        let output = match copyout::prepare(context, memory, [Some(UserSlot::new(address, length))])
        {
            Ok(output) => output,
            Err(refusal) => {
                return Ok(IpcHostOutcome::OwnerMemory {
                    token,
                    outcome: Box::new(refusal.into_outcome()),
                });
            }
        };
        let (landed, effect) = output.commit_retaining([&bytes[offset..offset + length]]);
        if landed.is_err() {
            drop(effect);
            finish(region, token, wake)?;
            return Ok(complete(LINUX_EFAULT.guest_retval()));
        }
        op.progress.written += length as u64;
        // As for HostCopy::land below, terminal publication must not pass
        // the guest write before its retained cursor is published.
        let updated = region.update_operation(&token, op);
        drop(effect);
        updated?;
    }
    finish(region, token, wake)?;
    Ok(complete(op.result))
}

/// Most bytes one host step can move (the largest pipe capacity).
const HOST_STEP_BYTES: u64 = 1 << 20;

/// The host's user copies for one step. Touching guest memory may fault
/// pages in and pause the address space, which must never happen under an
/// IPC lock: copies in are served from a prefix read before the lock, and
/// copies out are validated under it and landed after it.
struct HostCopy<'m, M: carrick_guest_mem::CurrentMmMemory> {
    output: HostOutput<'m, M>,
    prefetch_va: u64,
    prefetch: Vec<u8>,
    pending: Vec<(u64, Vec<u8>)>,
}

enum HostOutput<'m, M: carrick_guest_mem::CurrentMmMemory> {
    Legacy(&'m mut M),
    Prepared {
        copyout: crate::dispatch::copyout::PreparedCopyout<'m, M, 1>,
        base: u64,
        capacity: usize,
    },
}

impl<M: carrick_guest_mem::CurrentMmMemory> UserCopy for HostCopy<'_, M> {
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
        let writable = match &self.output {
            HostOutput::Legacy(memory) => memory.guest_range_is_writable(dst_va, src.len()),
            HostOutput::Prepared { base, capacity, .. } => dst_va
                .checked_sub(*base)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| offset.checked_add(src.len()))
                .is_some_and(|end| end <= *capacity),
        };
        if !writable {
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
    /// Imported vectors can end their readable prefix between logical page
    /// boundaries. Preserve that exact prefix rather than asking the boolean
    /// user-copy interface to accept an entire logical page.
    fn copy_prefetched_prefix(&mut self, dst: &mut [u8], at: u64) -> usize {
        let Some(start) = at
            .checked_sub(self.prefetch_va)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            return 0;
        };
        let Some(remaining) = self.prefetch.get(start..) else {
            return 0;
        };
        let count = remaining.len().min(dst.len());
        dst[..count].copy_from_slice(&remaining[..count]);
        count
    }

    /// Read the longest readable prefix of `[va, va+len)` before any lock.
    fn prefetch(&mut self, va: u64, len: u64) {
        let HostOutput::Legacy(memory) = &self.output else {
            return;
        };
        self.prefetch_va = va;
        self.prefetch.clear();
        let mut at = 0u64;
        while at < len {
            let n = (len - at).min(4096 - (va + at) % 4096);
            match memory.read_bytes(va + at, n as usize) {
                Ok(bytes) => self.prefetch.extend_from_slice(&bytes),
                Err(_) => break,
            }
            at += n;
        }
    }

    fn land(self) -> (bool, Option<crate::dispatch::copyout::OwnerEffect>) {
        match self.output {
            HostOutput::Prepared { copyout, .. } => {
                if self.pending.is_empty() {
                    return (true, copyout.cancel_retaining());
                }
                let bytes: Vec<u8> = self
                    .pending
                    .into_iter()
                    .flat_map(|(_, bytes)| bytes)
                    .collect();
                let (landed, effect) = copyout.commit_retaining([&bytes]);
                (landed.is_ok(), effect)
            }
            HostOutput::Legacy(memory) => {
                let mut landed = true;
                for (va, bytes) in self.pending {
                    landed &= memory.write_bytes(va, &bytes).is_ok();
                }
                (landed, None)
            }
        }
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
    context: &crate::kernel::KernelContext,
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
        IpcHandback::Restart if op.kind == IpcOpKind::PollWait => {}
        IpcHandback::Restart => {
            let op = finish(region, token, wake)?;
            return Ok(IpcHostOutcome::Restart(IpcRestart::Original {
                x0: op.orig_x0,
                nr: op.nr,
            }));
        }
        IpcHandback::Continue => {}
        IpcHandback::None => return Err(IpcError::Corrupt),
    }
    if op.mm != mm {
        // A stale or foreign address space never receives these bytes.
        return Err(IpcError::Stale);
    }
    if let Some(cause) = signal {
        return interrupt(context, region, token, mm, memory, cause, wake);
    }
    if op.kind == IpcOpKind::PollWait {
        return complete_poll(context, region, token, op, memory, None, wake);
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
    let output = if matches!(op.kind, IpcOpKind::PipeRead | IpcOpKind::EventFdRead)
        && memory.user_memory_venue() == carrick_guest_mem::UserMemoryVenue::Owner
    {
        use crate::dispatch::copyout::{self, UserSlot};
        let base = op.buf.0.wrapping_add(op.progress.written);
        // One page-bounded permit, before locking the source. A read may
        // return this exact prefix; no byte outside it can be consumed.
        let capacity = if op.kind == IpcOpKind::EventFdRead {
            8
        } else {
            op.progress
                .remaining()
                .min(
                    (carrick_el1::substrate::ipc::USER_COPY_GRANULE
                        - base % carrick_el1::substrate::ipc::USER_COPY_GRANULE)
                        as usize,
                )
                .min(copyout::COPYOUT_MAX_BYTES)
        };
        let copyout = match copyout::prepare(context, memory, [Some(UserSlot::new(base, capacity))])
        {
            Ok(copyout) => copyout,
            Err(refusal) => {
                return Ok(IpcHostOutcome::OwnerMemory {
                    token,
                    outcome: Box::new(refusal.into_outcome()),
                });
            }
        };
        let capacity = copyout.secured_capacity(0);
        HostOutput::Prepared {
            copyout,
            base,
            capacity,
        }
    } else {
        HostOutput::Legacy(memory)
    };
    let mut user = HostCopy {
        output,
        prefetch_va: 0,
        prefetch: Vec::new(),
        pending: Vec::new(),
    };
    let vector_input = region.has_vectors(&token)?;
    if op.kind == IpcOpKind::PipeWrite {
        let length = (op.progress.remaining() as u64).min(HOST_STEP_BYTES);
        if vector_input {
            // Gather the imported source before acquiring the pipe lock. The
            // logical prefix is independent of descriptor reuse or mutation.
            let mut bytes = vec![0; length as usize];
            let copied = region
                .copy_vector_input(&token, op.progress.written, &mut bytes, |dst, address| {
                    user.prefetch(address.0, dst.len() as u64);
                    let available = user.prefetch.len().min(dst.len());
                    dst[..available].copy_from_slice(&user.prefetch[..available]);
                    available
                })
                .map_err(IpcError::from)?;
            bytes.truncate(copied);
            user.prefetch = bytes;
            user.prefetch_va = op.progress.written;
        } else {
            let va = op.buf.0.wrapping_add(op.progress.written);
            user.prefetch(va, length);
        }
    }
    let (status, published) = {
        let mut guard = region.lock(object, &HostIpcWait)?;
        let mut copy = PrefixCopy::new(&mut user);
        let (status, wake_set) = if vector_input {
            carrick_el1::substrate::ipc::transfer_with_input(
                &mut guard,
                &mut op,
                &mut copy,
                |copy, at, dst| copy.user.copy_prefetched_prefix(dst, at),
            )?
        } else {
            transfer(&mut guard, &mut op, &mut copy)?
        };
        (status, guard.publish(wake_set))
    };
    let (landed, effect) = user.land();
    region.update_operation(&token, op)?;
    drop(effect);
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
                deadline: op.deadline.get(),
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
