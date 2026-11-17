//! Advisory file locks served in the ring (#231): fcntl(2) record locks
//! (`F_GETLK`, `F_SETLK`, `F_SETLKW`), open file description locks
//! (`F_OFD_*`) and flock(2), on the host-file descriptions the carrier
//! stamped with their file identity when it opened them.
//!
//! Every lock lives in the zone's one table
//! ([`carrick_el1_abi::ipc::IpcRegion::file_locks`]), whatever process or
//! CPU takes it. A record lock belongs to the caller's descriptor table, an
//! OFD lock or flock to the pinned description. A call that must wait
//! (`F_SETLKW`, flock without `LOCK_NB`) never spins and never holds the
//! CPU: it records an [`IpcOpKind::FileLockWait`] operation that pins its
//! description, enrols on the lock object's `Readable` lane under the
//! table's lock and parks. Every release publishes that lane; a woken call
//! re-enters with its original registers, takes its operation back before
//! any descriptor lookup, and probes the table once more. A signal ends the
//! wait with EINTR, restartable under `SA_RESTART` (signal(7)).
//!
//! Not served here (left a counted ENOSYS): an `l_whence` of `SEEK_CUR` or
//! `SEEK_END`, whose base lives with the host description, and a
//! description the carrier did not stamp. `F_SETLKW` reports no EDEADLK.

use super::{
    EL1_WAIT, IpcExecution, IpcServed, IpcVenue, Parked, finish_native, mm_key, park,
    retain_native_operation, set_result, settle_native_release, snapshot, task_key,
};
use crate::dispatch::GuestDispatchFrame;
use carrick_el1::substrate::file::UserCopy;
use carrick_el1::substrate::ipc::from_sched_token;
use carrick_el1_abi::ipc::fd::record_lock::{
    Lock, LockClass, LockKind, LockOwner, LockPid, LockRange, SetRefusal,
};
use carrick_el1_abi::ipc::fd::{AccessMode, Error as FdError, Fd, TableId};
use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{IpcOpKind, IpcOpToken, IpcOperation, IpcRegion, IpcUserVa, OfdPin};
use carrick_personality_linux::dispatch::SyscallFrame;

/// One lock call, decoded before any effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockCall {
    /// `F_GETLK` / `F_OFD_GETLK`: report the lock that would block.
    Query { ofd: bool },
    /// `F_SETLK`/`F_SETLKW` and their OFD forms, by the `l_type` they carry.
    Set { ofd: bool, wait: bool },
    /// flock(2) `LOCK_SH`/`LOCK_EX`/`LOCK_UN`, with or without `LOCK_NB`.
    Flock { kind: Option<LockKind>, wait: bool },
}

impl LockCall {
    /// The fcntl(2) commands and flock(2) this owner serves; `None` for
    /// every other call.
    pub(crate) fn decode(canonical: u64, arg1: u64) -> Option<Self> {
        use carrick_abi::{
            LINUX_F_GETLK, LINUX_F_OFD_GETLK, LINUX_F_OFD_SETLK, LINUX_F_OFD_SETLKW, LINUX_F_SETLK,
            LINUX_F_SETLKW,
        };
        if canonical == carrick_personality_linux::crossing::nr::FLOCK.raw() {
            use carrick_abi::{LINUX_LOCK_EX, LINUX_LOCK_NB, LINUX_LOCK_SH, LINUX_LOCK_UN};
            // An unknown operation is decoded too: it is flock's EINVAL.
            let kind = match arg1 & !LINUX_LOCK_NB {
                LINUX_LOCK_SH => Some(LockKind::Read),
                LINUX_LOCK_EX => Some(LockKind::Write),
                LINUX_LOCK_UN => None,
                _ => Some(LockKind::Read),
            };
            return Some(Self::Flock {
                kind,
                wait: arg1 & LINUX_LOCK_NB == 0,
            });
        }
        if canonical != carrick_personality_linux::crossing::nr::FCNTL.raw() {
            return None;
        }
        Some(match arg1 {
            LINUX_F_GETLK => Self::Query { ofd: false },
            LINUX_F_OFD_GETLK => Self::Query { ofd: true },
            LINUX_F_SETLK => Self::Set {
                ofd: false,
                wait: false,
            },
            LINUX_F_SETLKW => Self::Set {
                ofd: false,
                wait: true,
            },
            LINUX_F_OFD_SETLK => Self::Set {
                ofd: true,
                wait: false,
            },
            LINUX_F_OFD_SETLKW => Self::Set {
                ofd: true,
                wait: true,
            },
            _ => return None,
        })
    }

    fn valid_flock_operation(arg1: u64) -> bool {
        use carrick_abi::{LINUX_LOCK_EX, LINUX_LOCK_NB, LINUX_LOCK_SH, LINUX_LOCK_UN};
        matches!(
            arg1 & !LINUX_LOCK_NB,
            LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN
        )
    }
}

/// `F_GETLK`'s answer: the caller's `struct flock`, rewritten, for the
/// native owner's copyout.
pub(crate) struct LockQueryOutput {
    pub address: u64,
    pub flock: carrick_abi::LinuxFlock64,
}

/// What a decoded `struct flock` asks for.
enum Wanted {
    Lock(LockKind),
    Unlock,
}

/// Decode the caller's `struct flock` (`SEEK_SET` only), as fcntl(2)
/// validates it before acting: `Err` is the errno to return, `Ok(None)`
/// a base this owner does not serve.
fn decode_flock(
    flock: &carrick_abi::LinuxFlock64,
    ofd: bool,
) -> Result<Option<(Wanted, LockRange)>, i64> {
    use carrick_abi::{LINUX_F_RDLCK, LINUX_F_UNLCK, LINUX_F_WRLCK, LINUX_SEEK_SET};
    let einval = carrick_syscall_abi::LINUX_EINVAL.guest_retval();
    let wanted = match i32::from(flock.l_type) {
        LINUX_F_RDLCK => Wanted::Lock(LockKind::Read),
        LINUX_F_WRLCK => Wanted::Lock(LockKind::Write),
        LINUX_F_UNLCK => Wanted::Unlock,
        _ => return Err(einval),
    };
    // An OFD lock has no owning process: its l_pid must be zero.
    if ofd && flock.l_pid != 0 {
        return Err(einval);
    }
    let whence = flock.l_whence;
    if whence as u64 != LINUX_SEEK_SET {
        // SEEK_CUR and SEEK_END need the host description's offset or
        // size; any other base is fcntl's EINVAL.
        return if (1..=2).contains(&whence) {
            Ok(None)
        } else {
            Err(einval)
        };
    }
    let (start, len) = (flock.l_start, flock.l_len);
    LockRange::from_posix(0, start, len)
        .map(|range| Some((wanted, range)))
        .map_err(|_| einval)
}

/// Serve one advisory lock call of the running native task on its ring
/// table `table`. A query's answer is left in `output` for the caller's
/// copyout. `Forward` is a counted ENOSYS for the caller (or, with the
/// user's copy-in refusal set, its input wait); nothing took effect.
#[allow(clippy::too_many_lines)]
pub(crate) fn serve_file_lock<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    table: TableId,
    output: &mut Option<LockQueryOutput>,
) -> IpcServed {
    let canonical = frame.canonical_ordinal().raw();
    let fd_arg = super::argument_word(frame, 0);
    let arg1 = super::argument_word(frame, 1);
    let arg2 = super::argument_word(frame, 2);
    let Some(call) = LockCall::decode(canonical, arg1) else {
        return IpcServed::Forward;
    };
    let syscall_nr = frame.native_number().raw() as u32;
    let region = &venue.region;
    let authority = region.fd(EL1_WAIT);

    // A woken wait takes its own operation back before any descriptor
    // lookup: the description it pinned is the one it locks.
    let mut retained = match sched.take_object_operation() {
        Err(_) => return IpcServed::Forward,
        Ok(None) => None,
        Ok(Some(operation)) => {
            let Some(token) = from_sched_token(operation) else {
                return IpcServed::Forward;
            };
            let Ok(op) = region.operation(&token) else {
                return IpcServed::Forward;
            };
            if op.kind != IpcOpKind::FileLockWait
                || op.task != task_key(sched.task())
                || op.mm != mm_key(sched.task())
                || op.nr != syscall_nr
            {
                retain_native_operation(sched, token);
                crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding);
            }
            let reason = sched
                .zone()
                .slot(sched.slot())
                .current()
                .and_then(|id| sched.zone().record(id).handback());
            if reason == Some(carrick_sched_core::Handback::Signal) && user.interrupt_pending_wait()
            {
                finish_native(sched, token, region);
                set_result(
                    frame,
                    carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64,
                );
                sched.mark_restart(frame, op.orig_x0);
                return IpcServed::Returned { switched: false };
            }
            Some((token, op))
        }
    };

    // The description: the retained wait's pin, or a fresh one.
    let retained_pin = retained.as_ref().map(|(_, op)| op.pin);
    let (pin_key, description, mut fresh_pin) = if let Some(raw) = retained_pin {
        let pin = OfdPin::from_raw(raw);
        let pinned = authority.pinned(&pin);
        let key = pin.key();
        let _ = pin.into_raw();
        match (pinned, retained.take()) {
            (Ok(description), held) => {
                retained = held;
                (key, description, None)
            }
            (Err(_), held) => {
                if let Some((token, _)) = held {
                    retain_native_operation(sched, token);
                }
                crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding);
            }
        }
    } else {
        match authority.pin(table, Fd(fd_arg as i32)) {
            Ok((pin, description)) => (pin.key(), description, Some(pin)),
            Err(FdError::BadFd) => {
                set_result(
                    frame,
                    carrick_syscall_abi::LINUX_EBADF.guest_retval() as u64,
                );
                return IpcServed::Returned { switched: false };
            }
            Err(_) => return IpcServed::Forward,
        }
    };
    let identity = match fresh_pin.as_ref() {
        Some(pin) => authority.pinned_identity(pin),
        None => retained
            .as_ref()
            .map(|(_, op)| {
                let pin = OfdPin::from_raw(op.pin);
                let identity = authority.pinned_identity(&pin);
                let _ = pin.into_raw();
                identity
            })
            .unwrap_or(Err(FdError::BadFd)),
    };
    let Ok(Some(file)) = identity else {
        // Not a file the carrier named: nothing here can lock it.
        drop_hold(sched, region, retained.take(), fresh_pin.take());
        return IpcServed::Forward;
    };

    // Input after the descriptor (EBADF first, as Linux) and before any
    // effect.
    let mut flock = carrick_abi::LinuxFlock64::default();
    let request = match call {
        LockCall::Flock { kind, wait } => {
            if !LockCall::valid_flock_operation(arg1) {
                return finish_with(
                    sched,
                    frame,
                    region,
                    retained.take(),
                    fresh_pin.take(),
                    carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                );
            }
            (
                kind.map_or(Wanted::Unlock, Wanted::Lock),
                LockRange::WHOLE_FILE,
                wait,
            )
        }
        LockCall::Query { ofd } | LockCall::Set { ofd, .. } => {
            let bytes = zerocopy::IntoBytes::as_mut_bytes(&mut flock);
            if !user.copy_in(bytes, arg2) {
                if user.has_copyin_refusal() && retained.is_none() {
                    drop_hold(sched, region, None, fresh_pin.take());
                    return IpcServed::Forward;
                }
                return finish_with(
                    sched,
                    frame,
                    region,
                    retained.take(),
                    fresh_pin.take(),
                    carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
                );
            }
            match decode_flock(&flock, ofd) {
                Ok(Some((wanted, range))) => (
                    wanted,
                    range,
                    matches!(call, LockCall::Set { wait: true, .. }),
                ),
                Ok(None) => {
                    drop_hold(sched, region, retained.take(), fresh_pin.take());
                    return IpcServed::Forward;
                }
                Err(errno) => {
                    return finish_with(
                        sched,
                        frame,
                        region,
                        retained.take(),
                        fresh_pin.take(),
                        errno,
                    );
                }
            }
        }
    };
    let (wanted, range, blocking) = request;

    // fcntl(2) and flock(2): an O_PATH descriptor locks nothing, and a
    // record lock needs the access its type names.
    let ebadf = carrick_syscall_abi::LINUX_EBADF.guest_retval();
    let access = description.access;
    let refused = match (&call, &wanted) {
        _ if access == AccessMode::Path => true,
        (LockCall::Set { .. }, Wanted::Lock(LockKind::Read)) => access == AccessMode::WriteOnly,
        (LockCall::Set { .. }, Wanted::Lock(LockKind::Write)) => access == AccessMode::ReadOnly,
        _ => false,
    };
    if refused {
        return finish_with(
            sched,
            frame,
            region,
            retained.take(),
            fresh_pin.take(),
            ebadf,
        );
    }

    let (class, owner) = match call {
        LockCall::Flock { .. } => (LockClass::Flock, LockOwner::description(pin_key)),
        LockCall::Query { ofd: true } | LockCall::Set { ofd: true, .. } => {
            (LockClass::Record, LockOwner::description(pin_key))
        }
        _ => (LockClass::Record, LockOwner::table(table)),
    };
    let pid = LockPid::new(sched.task().visible_pid().unwrap_or(0));

    loop {
        let Ok(mut locks) = region.file_locks(&EL1_WAIT) else {
            drop_hold(sched, region, retained.take(), fresh_pin.take());
            return IpcServed::Forward;
        };
        let owners = region.fd(EL1_WAIT);
        let kind = match wanted {
            Wanted::Lock(kind) => kind,
            Wanted::Unlock => {
                let released = match call {
                    // F_GETLK with F_UNLCK is fcntl's EINVAL.
                    LockCall::Query { .. } => {
                        drop(locks);
                        return finish_with(
                            sched,
                            frame,
                            region,
                            retained.take(),
                            fresh_pin.take(),
                            carrick_syscall_abi::LINUX_EINVAL.guest_retval(),
                        );
                    }
                    _ => locks.table().unlock(file, owner, class, range),
                };
                let result = match released {
                    Ok(true) => {
                        let wake = locks.released();
                        drop(locks);
                        super::notify_native_wake(
                            wake,
                            Some((sched.zone(), sched.slot())),
                            sched.task(),
                        );
                        0
                    }
                    Ok(false) => 0,
                    Err(_) => carrick_abi::LINUX_ENOLCK.guest_retval(),
                };
                return finish_with(
                    sched,
                    frame,
                    region,
                    retained.take(),
                    fresh_pin.take(),
                    result,
                );
            }
        };
        let request = Lock {
            file,
            owner,
            class,
            kind,
            range,
            pid,
        };
        if let LockCall::Query { .. } = call {
            let conflict = locks.table().conflict(&request, &owners);
            drop(locks);
            match conflict {
                Some(holder) => {
                    flock.l_type = match holder.kind {
                        LockKind::Read => carrick_abi::LINUX_F_RDLCK as i16,
                        LockKind::Write => carrick_abi::LINUX_F_WRLCK as i16,
                    };
                    flock.l_whence = carrick_abi::LINUX_SEEK_SET as i16;
                    flock.l_start = holder.range.start() as i64;
                    flock.l_len = holder.range.posix_len();
                    // An OFD lock has no owning process (fcntl(2)).
                    flock.l_pid = match holder.owner {
                        LockOwner::Description(_) => -1,
                        LockOwner::Table { .. } => holder.pid.raw() as i32,
                    };
                }
                None => flock.l_type = carrick_abi::LINUX_F_UNLCK as i16,
            }
            *output = Some(LockQueryOutput {
                address: arg2,
                flock,
            });
            return finish_with(sched, frame, region, retained.take(), fresh_pin.take(), 0);
        }
        let outcome = locks.table().set(request, &owners);
        let wake = outcome.released.then(|| locks.released());
        let blocked = match outcome.taken {
            Ok(()) => None,
            Err(SetRefusal::Full) => Some(carrick_abi::LINUX_ENOLCK.guest_retval()),
            Err(SetRefusal::Conflict(_)) if !blocking => {
                Some(carrick_syscall_abi::LINUX_EAGAIN.guest_retval())
            }
            Err(SetRefusal::Conflict(_)) => {
                // Enrol under the table's lock: a release after this
                // snapshot changes the lane's epoch, so the park returns at
                // once instead of missing the wake.
                let object = locks.handle();
                let Some(snap) = snapshot(sched, object, WaitFor::Readable) else {
                    drop(locks);
                    if let Some(wake) = wake {
                        super::notify_native_wake(
                            wake,
                            Some((sched.zone(), sched.slot())),
                            sched.task(),
                        );
                    }
                    drop_hold(sched, region, retained.take(), fresh_pin.take());
                    return IpcServed::Forward;
                };
                drop(locks);
                if let Some(wake) = wake {
                    super::notify_native_wake(
                        wake,
                        Some((sched.zone(), sched.slot())),
                        sched.task(),
                    );
                }
                let (token, op) = match retained.take() {
                    Some((token, mut op)) => {
                        op.object = object.to_raw();
                        (token, op)
                    }
                    None => {
                        let Some(pin) = fresh_pin.take() else {
                            crate::dispatch::invalid_completion(
                                crate::dispatch::NativeInvariant::EntryBinding,
                            );
                        };
                        let op = IpcOperation {
                            kind: IpcOpKind::FileLockWait,
                            pin: pin.into_raw(),
                            object: object.to_raw(),
                            task: task_key(sched.task()),
                            mm: mm_key(sched.task()),
                            buf: IpcUserVa(arg2),
                            orig_x0: fd_arg,
                            nr: syscall_nr,
                            ..IpcOperation::EMPTY
                        };
                        match region.begin_operation(op) {
                            Ok(token) => (token, op),
                            Err(_) => {
                                drop_hold(sched, region, None, Some(OfdPin::from_raw(op.pin)));
                                return IpcServed::Forward;
                            }
                        }
                    }
                };
                match park(
                    sched,
                    frame,
                    region,
                    token,
                    op,
                    object,
                    WaitFor::Readable,
                    snap,
                    None,
                    &mut || user.interrupt_pending_wait(),
                ) {
                    Parked::Done(served) => return served,
                    // A release raced the enrolment: probe once more.
                    Parked::Retry(token) => {
                        retained = Some((token, op));
                        continue;
                    }
                    Parked::Refused(token) => {
                        finish_native(sched, token, region);
                        return IpcServed::Forward;
                    }
                }
            }
        };
        drop(locks);
        if let Some(wake) = wake {
            super::notify_native_wake(wake, Some((sched.zone(), sched.slot())), sched.task());
        }
        return finish_with(
            sched,
            frame,
            region,
            retained.take(),
            fresh_pin.take(),
            blocked.unwrap_or(0),
        );
    }
}

/// Drop what the call holds (its retained operation or its fresh pin) and
/// complete it with `result`.
fn finish_with<E: IpcExecution>(
    sched: &mut E,
    frame: &mut E::Frame,
    region: &IpcRegion<'_>,
    retained: Option<(IpcOpToken, IpcOperation)>,
    pin: Option<OfdPin>,
    result: i64,
) -> IpcServed {
    drop_hold(sched, region, retained, pin);
    set_result(frame, result as u64);
    IpcServed::Returned { switched: false }
}

/// Release a retained operation (and its pin) or a fresh pin. A host
/// description's last reference found here retires through the deferred
/// host release, ending its OFD and flock locks on the way.
fn drop_hold<E: IpcExecution>(
    sched: &mut E,
    region: &IpcRegion<'_>,
    retained: Option<(IpcOpToken, IpcOperation)>,
    pin: Option<OfdPin>,
) {
    if let Some((token, _)) = retained {
        finish_native(sched, token, region);
    }
    if let Some(pin) = pin {
        let release = region
            .fd(EL1_WAIT)
            .unpin_filtered(pin, super::is_zone_releasable_backing)
            .unwrap_or_else(|_| {
                crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
            });
        settle_native_release(
            region,
            release,
            Some((sched.zone(), sched.slot())),
            sched.task(),
        )
        .unwrap_or_else(|_| {
            crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
        });
    }
}
