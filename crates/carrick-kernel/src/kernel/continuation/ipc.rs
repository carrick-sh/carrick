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
use carrick_el1_abi::ipc::pipe::{WaitFor, WakeSet};
use carrick_el1_abi::ipc::{
    IpcError, IpcHandback, IpcMmKey, IpcObjectHandle, IpcOpKind, IpcOpToken, IpcOperation,
    IpcRegion, IpcReleased, OfdPin, RawIpcOpToken,
};

/// The host waits for the short sections other parties hold object and
/// descriptor-table locks for (the zone's host lock policy).
pub use crate::el1_zone::HostLockWait as HostIpcWait;

/// How the host wakes an object's waiters after a state change it made (the
/// guest venue notifies under the object lock; the host uses its own
/// placement boundary). Called with no IPC lock held.
pub trait IpcHostWake {
    fn wake(&self, object: IpcObjectHandle, lanes: WakeSet);
}

/// Why a parked or handed-back operation stops before completing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcCause {
    /// A signal whose handler will run; `restart` is its `SA_RESTART`.
    Signal { restart: bool },
    /// A control action (job-control stop, exec/exit drain).
    Control,
}

/// What the host does with the thread after completing its operation.
#[derive(Debug, Eq, PartialEq)]
pub enum IpcHostOutcome {
    /// Return `result` after the SVC; `sigpipe` requests SIGPIPE too.
    Complete { result: i64, sigpipe: bool },
    /// No effect was taken: resume at the SVC with the original `x0` and
    /// syscall number (the call runs again).
    Restart { x0: u64, nr: u32 },
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

/// The outcome of stopping `op` for `cause` (pure policy).
pub fn interrupted(op: &IpcOperation, cause: IpcCause) -> IpcHostOutcome {
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
        IpcCause::Signal { restart: true } | IpcCause::Control => IpcHostOutcome::Restart {
            x0: op.orig_x0,
            nr: op.nr,
        },
    }
}

/// Retire the operation (consuming its token), drop its description pin and
/// perform a final release, waking the peer lanes. Exactly once: a second
/// finish of the same token is `Stale`.
pub fn finish(
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    wake: &impl IpcHostWake,
) -> Result<IpcOperation, IpcError> {
    let op = region.finish_operation(token)?;
    if op.pin.authority != 0 {
        let fd = region.fd(HostIpcWait);
        if let Some(description) = fd.unpin(OfdPin::from_raw(op.pin)).map_err(IpcError::Fd)?
            && let IpcReleased::Object { wake: w, freed } =
                region.release_backing(description.backing, &HostIpcWait)?
            && !freed
        {
            wake.wake(
                w.object,
                WakeSet {
                    readers: w.readers,
                    writers: w.writers,
                },
            );
        }
    }
    Ok(op)
}

/// Stop a parked or handed-back operation for `cause` and finish it.
pub fn interrupt(
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    cause: IpcCause,
    wake: &impl IpcHostWake,
) -> Result<IpcHostOutcome, IpcError> {
    let op = finish(region, token, wake)?;
    Ok(interrupted(&op, cause))
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
    wake: &impl IpcHostWake,
) -> Result<IpcHostOutcome, IpcError> {
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
    let (status, wake_set) = {
        let mut guard = region.lock(object, &HostIpcWait)?;
        let mut copy = PrefixCopy::new(&mut user);
        let step = transfer(&mut guard, &mut op, &mut copy)?;
        guard.publish(step.1);
        step
    };
    let landed = user.land();
    region.update_operation(&token, op)?;
    if wake_set.readers || wake_set.writers {
        wake.wake(object, wake_set);
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
