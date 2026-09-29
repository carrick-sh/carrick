//! Neutral mechanics that bind the shared IPC objects (`carrick_el1_abi::ipc`)
//! to the EL1 scheduler's object waits: wait identities, the operation-token
//! conversion, prefix-exact user copies, and one staged transfer step under
//! an object lock. No syscall numbers, errno values or flag decoding live
//! here; the Linux adapter (`personality::ipc`) decides what a step means.

use crate::substrate::file::UserCopy;
use carrick_el1_abi::ipc::pipe::{self, WaitFor, WakeSet};
use carrick_el1_abi::ipc::{
    IpcError, IpcObjectGuard, IpcObjectHandle, IpcOpKind, IpcOpToken, IpcOperation, RawIpcOpToken,
};
use carrick_sched_core::object_wait::{OBJECT_WAIT_QUEUES, ObjectWaitKey, OperationToken};

/// Granule at which user copies are split, so a fault ends a copy at an
/// exact page-aligned prefix (the smallest guest page size).
pub const USER_COPY_GRANULE: u64 = 4096;

/// The object wait queue of one readiness lane of one object incarnation:
/// queue `1 + 2 * index + lane` (index 0 is reserved by the scheduler), and
/// generation `object generation + 1` (the scheduler requires nonzero,
/// strictly increasing generations; object generations start at 0).
pub fn wait_key(object: IpcObjectHandle, lane: WaitFor) -> Option<ObjectWaitKey> {
    let lane = match lane {
        WaitFor::Readable => 0,
        WaitFor::Writable => 1,
    };
    let index = 1 + 2 * u64::from(object.index()) + lane;
    if index >= OBJECT_WAIT_QUEUES as u64 {
        return None;
    }
    ObjectWaitKey::new(index as u32, u64::from(object.generation()) + 1)
}

/// Move an owned IPC operation token into the scheduler's opaque form
/// (`index + 1`, `generation + 1`: the scheduler reserves zero). Ownership
/// comes back unchanged if the scheduler cannot represent it.
pub fn to_sched_token(token: IpcOpToken) -> Result<OperationToken, IpcOpToken> {
    let raw = token.into_raw();
    OperationToken::new(u64::from(raw.index) + 1, u64::from(raw.generation) + 1)
        .ok_or(IpcOpToken::from_raw(raw))
}

/// Move a scheduler token back into the IPC authority's form. `None` for a
/// token no IPC operation could have produced (it is not ours).
pub fn from_sched_token(token: OperationToken) -> Option<IpcOpToken> {
    let index = u32::try_from(token.index().checked_sub(1)?).ok()?;
    let generation = u32::try_from(token.generation().checked_sub(1)?).ok()?;
    Some(IpcOpToken::from_raw(RawIpcOpToken { index, generation }))
}

/// A user copy that reports the exact delivered prefix: the range is split
/// at [`USER_COPY_GRANULE`] boundaries and stops at the first piece the
/// underlying guarded copy refuses.
pub struct PrefixCopy<'a, U: UserCopy> {
    pub user: &'a mut U,
    /// Bytes delivered through this copier (structural accounting).
    pub copied: usize,
}

impl<'a, U: UserCopy> PrefixCopy<'a, U> {
    pub fn new(user: &'a mut U) -> Self {
        Self { user, copied: 0 }
    }

    fn pieces(
        va: u64,
        len: usize,
        mut piece: impl FnMut(u64, core::ops::Range<usize>) -> bool,
    ) -> usize {
        let mut done = 0;
        while done < len {
            let Some(at) = va.checked_add(done as u64) else {
                break;
            };
            let room = (USER_COPY_GRANULE - at % USER_COPY_GRANULE) as usize;
            let n = room.min(len - done);
            if !piece(at, done..done + n) {
                break;
            }
            done += n;
        }
        done
    }

    /// Copy `src` to user `va`; returns the bytes delivered.
    pub fn copy_out(&mut self, va: u64, src: &[u8]) -> usize {
        let user = &mut *self.user;
        let n = Self::pieces(va, src.len(), |at, r| user.copy_out(at, &src[r]));
        self.copied += n;
        n
    }

    /// Fill `dst` from user `va`; returns the bytes filled.
    pub fn copy_in(&mut self, dst: &mut [u8], va: u64) -> usize {
        let user = &mut *self.user;
        let len = dst.len();
        let n = Self::pieces(va, len, |at, r| user.copy_in(&mut dst[r], at));
        self.copied += n;
        n
    }
}

/// How one transfer step under the object lock ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepStatus {
    /// The operation is complete (`op.progress.written` is its count).
    Complete,
    /// A read found no bytes and no writer.
    EndOfFile,
    /// The operation must wait for this lane (after any recorded progress).
    Blocked(WaitFor),
    /// No reader remains (after any recorded progress).
    Broken,
    /// A user copy delivered nothing in this step (after any progress).
    Fault,
    /// The object rejected the value (an all-ones counter write).
    Invalid,
}

/// Run `op` against its locked object as far as it can go without waiting:
/// staged copies commit only delivered bytes, and progress is recorded in
/// `op.progress`. Returns the status and every wake the step owes.
pub fn transfer<U: UserCopy>(
    guard: &mut IpcObjectGuard<'_>,
    op: &mut IpcOperation,
    copy: &mut PrefixCopy<'_, U>,
) -> Result<(StepStatus, WakeSet), IpcError> {
    let buf = op.buf.0;
    let mut wake = WakeSet::default();
    let mut owe = |w: WakeSet| {
        wake.readers |= w.readers;
        wake.writers |= w.writers;
    };
    let status = match op.kind {
        IpcOpKind::PipeRead => {
            let mut p = guard.pipe()?;
            let base = buf.wrapping_add(op.progress.written);
            let mut at = 0u64;
            let step = p.read_with(op.progress.remaining(), |chunk| {
                let n = copy.copy_out(base.wrapping_add(at), chunk);
                at += n as u64;
                n
            });
            owe(step.wake);
            match step.result {
                Ok(0) => StepStatus::EndOfFile,
                Ok(n) => {
                    op.progress.written += n as u64;
                    StepStatus::Complete
                }
                Err(e) => blocked_or(e)?,
            }
        }
        IpcOpKind::PipeWrite => {
            let mut p = guard.pipe()?;
            loop {
                let step = p.write_progress(&mut op.progress, |at, dst| {
                    copy.copy_in(dst, buf.wrapping_add(at as u64))
                });
                owe(step.wake);
                match step.result {
                    Ok(_) if op.progress.is_complete() => break StepStatus::Complete,
                    Ok(_) => continue,
                    Err(e) => break blocked_or(e)?,
                }
            }
        }
        IpcOpKind::EventFdRead => {
            let e = guard.eventfd()?;
            let step = e.read_with(|value| {
                let bytes = value.to_ne_bytes();
                copy.copy_out(buf, &bytes) == bytes.len()
            });
            owe(step.wake);
            match step.result {
                Ok(_) => {
                    op.progress.written = op.progress.len;
                    StepStatus::Complete
                }
                Err(e) => blocked_or(e)?,
            }
        }
        IpcOpKind::EventFdWrite => {
            let mut bytes = [0u8; 8];
            if copy.copy_in(&mut bytes, buf) != bytes.len() {
                StepStatus::Fault
            } else {
                let e = guard.eventfd()?;
                let step = e.try_write(u64::from_ne_bytes(bytes));
                owe(step.wake);
                match step.result {
                    Ok(()) => {
                        op.progress.written = op.progress.len;
                        StepStatus::Complete
                    }
                    Err(e) => blocked_or(e)?,
                }
            }
        }
        IpcOpKind::None => return Err(IpcError::Corrupt),
    };
    Ok((status, wake))
}

fn blocked_or(e: pipe::Error) -> Result<StepStatus, IpcError> {
    match e {
        pipe::Error::WouldBlock(lane) => Ok(StepStatus::Blocked(lane)),
        pipe::Error::BrokenPipe => Ok(StepStatus::Broken),
        pipe::Error::Fault => Ok(StepStatus::Fault),
        pipe::Error::Invalid => Ok(StepStatus::Invalid),
        other => Err(IpcError::Object(other)),
    }
}
