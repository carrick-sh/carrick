//! Filesystem locking and descriptor control syscalls and helpers: fcntl, flock,
//! POSIX classic record locks, open-file description (OFD) locks, leases,
//! seals, and FASYNC (signal-driven I/O). Split out of `dispatch/fs.rs` as
//! `impl SyscallDispatcher` methods.

use super::*;
use std::sync::Arc;

struct RecordLockRequest<'a, M> {
    kernel: &'a crate::kernel::KernelContext,
    memory: &'a mut M,
    tid: crate::thread::ThreadId,
    host_fd: i32,
    desc_ptr: usize,
    linux_cmd: u64,
    arg: u64,
}

/// Forward a classic POSIX record lock (F_SETLK/F_SETLKW/F_GETLK) on a
/// host-backed fd to the host kernel's real `fcntl` locking, translating the
/// `struct flock` between the Linux-aarch64 and macOS layouts (which differ in
/// BOTH field order and the `l_type` constants). `host_syscall_errno` maps the
/// host errno back to Linux (covering the EAGAIN↔EDEADLK number swap).
///
/// Linux aarch64 flock (32 bytes): l_type:i16@0, l_whence:i16@2, l_start:i64@8,
///   l_len:i64@16, l_pid:i32@24. l_type: RDLCK=0, WRLCK=1, UNLCK=2.
/// macOS flock (`libc::flock`): l_start:i64, l_len:i64, l_pid:i32, l_type:i16,
///   l_whence:i16. l_type: RDLCK=1, UNLCK=2, WRLCK=3. cmd: GETLK=7/SETLK=8/SETLKW=9.
fn forward_record_lock<M: CurrentMmMemory>(
    this: &SyscallDispatcher,
    req: RecordLockRequest<'_, M>,
) -> DispatchOutcome {
    // OFD locks (F_OFD_*) are owned by the open file description, not the process.
    // macOS has them natively (F_OFD_SETLK/SETLKW/GETLK = 90/91/92), so we forward
    // exactly like the classic commands; the only divergence is that F_OFD_GETLK
    // reports l_pid = -1 for a conflicting lock (OFD locks are not process-owned).
    let is_ofd = matches!(
        req.linux_cmd,
        LINUX_F_OFD_GETLK | LINUX_F_OFD_SETLK | LINUX_F_OFD_SETLKW
    );

    let flock: LinuxFlock64 = match req.memory.read_struct(req.arg) {
        Ok(f) => f,
        Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
    };
    let l_type_linux = flock.l_type;
    let l_whence = flock.l_whence;
    let l_start = flock.l_start;
    let l_len = flock.l_len;

    // l_whence must be SEEK_SET/SEEK_CUR/SEEK_END; Linux rejects anything else
    // with EINVAL in flock_to_posix_lock, before attempting the lock.
    if !(0..=2).contains(&l_whence) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    // Linux rejects an out-of-range `l_type` with EINVAL in
    // `flock_to_posix_lock`, before attempting the lock. The logical table below
    // reads the field as RDLCK/WRLCK/UNLCK, so the range check must stay even
    // though nothing translates it to a host `F_*LCK` any more.
    if !matches!(
        i32::from(l_type_linux),
        LINUX_F_RDLCK | LINUX_F_WRLCK | LINUX_F_UNLCK
    ) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    if !matches!(
        req.linux_cmd,
        LINUX_F_GETLK
            | LINUX_F_SETLK
            | LINUX_F_SETLKW
            | LINUX_F_OFD_GETLK
            | LINUX_F_OFD_SETLK
            | LINUX_F_OFD_SETLKW
    ) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }

    {
        let file = match logical_record_lock_file(req.host_fd) {
            Ok(file) => file,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let range = match normalize_logical_record_lock_range(req.host_fd, l_whence, l_start, l_len)
        {
            Ok(range) => range,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let owner = if is_ofd {
            LogicalRecordLockOwner::Ofd(req.desc_ptr)
        } else {
            LogicalRecordLockOwner::from(req.kernel.task().key())
        };
        if l_type_linux == LINUX_F_UNLCK as i16 {
            if matches!(req.linux_cmd, LINUX_F_GETLK | LINUX_F_OFD_GETLK) {
                return DispatchOutcome::errno(LINUX_EINVAL);
            }
            this.fs.classic_record_locks.unlock(&file, owner, range);
            return DispatchOutcome::Returned { value: 0 };
        }
        let request = LogicalRecordLockRequest {
            file,
            owner,
            range,
            write: l_type_linux == LINUX_F_WRLCK as i16,
        };
        if matches!(req.linux_cmd, LINUX_F_GETLK | LINUX_F_OFD_GETLK) {
            let conflict = this.fs.classic_record_locks.conflict(&request);
            return write_logical_record_lock_conflict(
                req.kernel, req.memory, req.arg, conflict, is_ofd,
            );
        }
        match this.fs.classic_record_locks.try_set(request.clone()) {
            Ok(()) => DispatchOutcome::Returned { value: 0 },
            Err(errno) if matches!(req.linux_cmd, LINUX_F_SETLK | LINUX_F_OFD_SETLK) => {
                DispatchOutcome::errno(errno)
            }
            Err(errno) if errno != LINUX_EAGAIN => DispatchOutcome::errno(errno),
            Err(_) => {
                let wait = LogicalRecordLockWait::new(
                    Arc::clone(&this.fs.classic_record_locks),
                    request,
                    req.tid,
                );
                DispatchOutcome::BlockingRecordLock(crate::dispatch::BlockingRecordLock::logical(
                    wait,
                ))
            }
        }
    }
}

/// Front-door `struct flock` validation Linux performs for F_GETLK/F_SETLK/
/// F_SETLKW BEFORE acting on the lock, regardless of the fd's backing: a bad
/// pointer → EFAULT, an out-of-range `l_type` or `l_whence` → EINVAL. carrick's
/// non-host-backed no-op path (e.g. fd=1, in-memory/synthetic files) skipped
/// this, so LTP fcntl13 (fd=1 with a bad address / bad l_whence) wrongly
/// succeeded. Mirrors the host-backed path's checks in `forward_record_lock`.
fn validate_flock_arg<M: CurrentMmMemory>(memory: &M, arg: u64) -> Result<(), LinuxErrno> {
    let flock: LinuxFlock64 = memory.read_struct(arg).map_err(|_| LINUX_EFAULT)?;
    let l_type = flock.l_type;
    let l_whence = flock.l_whence;
    // l_type: RDLCK=0/WRLCK=1/UNLCK=2; l_whence: SEEK_SET=0/SEEK_CUR=1/SEEK_END=2.
    if !(0..=2).contains(&l_type) || !(0..=2).contains(&l_whence) {
        return Err(LINUX_EINVAL);
    }
    Ok(())
}

/// Same-file identity used for F_SETLEASE conflict accounting (see
/// [`SyscallDispatcher::same_file_other_openers`]). Two open descriptions
/// conflict for lease purposes iff they name the same underlying file: the host
/// inode under `--fs host`, or the guest open-path for the in-memory backing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum LeaseFileId {
    Inode { dev: u64, ino: u64 },
    Path(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LogicalRecordLockOwner {
    Process { pid: i32, serial: u64 },
    Ofd(usize),
}

impl LogicalRecordLockOwner {
    fn task_key(&self) -> Option<crate::kernel::TaskKey> {
        match self {
            Self::Process { pid, serial } => Some(crate::kernel::TaskKey {
                id: crate::kernel::TaskId::from_abi_positive(*pid).ok()?,
                serial: crate::kernel::TaskSerial::from_raw_u64(*serial)?,
            }),
            Self::Ofd(_) => None,
        }
    }

    pub(crate) fn conflicts_with(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Process {
                    pid: p1,
                    serial: s1,
                },
                Self::Process {
                    pid: p2,
                    serial: s2,
                },
            ) => p1 != p2 || s1 != s2,
            (Self::Ofd(d1), Self::Ofd(d2)) => d1 != d2,
            // A POSIX lock ALWAYS conflicts with an OFD lock (even from the same process).
            (Self::Process { .. }, Self::Ofd(_)) | (Self::Ofd(_), Self::Process { .. }) => true,
        }
    }
}

impl From<crate::kernel::TaskKey> for LogicalRecordLockOwner {
    fn from(key: crate::kernel::TaskKey) -> Self {
        Self::Process {
            pid: key.id.raw(),
            serial: key.serial.raw(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogicalRecordLockRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl LogicalRecordLockRange {
    pub(crate) fn overlaps(&self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogicalRecordLock {
    pub(crate) file: LeaseFileId,
    pub(crate) owner: LogicalRecordLockOwner,
    pub(crate) range: LogicalRecordLockRange,
    pub(crate) write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogicalFlock {
    pub(crate) file: LeaseFileId,
    pub(crate) owner: usize,
    pub(crate) write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogicalRecordLockRequest {
    pub(crate) file: LeaseFileId,
    pub(crate) owner: LogicalRecordLockOwner,
    pub(crate) range: LogicalRecordLockRange,
    pub(crate) write: bool,
}

/// Token identifying one waiting `LogicalRecordLockRequest` in the wait-for
/// graph, minted by [`LogicalRecordLocks::mint_wait_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RecordLockWaitId(pub(crate) u64);

#[derive(Default)]
pub(crate) struct LogicalRecordLockState {
    pub(crate) locks: Vec<LogicalRecordLock>,
    pub(crate) flocks: Vec<LogicalFlock>,
    /// `wait → (waiting owner, owner it is blocked on)` for every request
    /// that is currently blocked — whether it is parked on a host thread in
    /// `wait_set_interruptibly` or re-polled by the HVPatch reactor through
    /// `LogicalRecordLockWait::try_acquire`. Both paths go through
    /// `poll_set_locked`, the only place an edge is published.
    pub(crate) waiting_on: std::collections::HashMap<
        RecordLockWaitId,
        (LogicalRecordLockOwner, LogicalRecordLockOwner),
    >,
}

impl LogicalRecordLockState {
    /// The owner `owner` is currently blocked on, if any. With several waits
    /// per owner this is any one of them; it exists for tests and diagnostics,
    /// the deadlock walk itself enumerates every edge.
    #[cfg(test)]
    pub(crate) fn waits_on(&self, owner: LogicalRecordLockOwner) -> Option<LogicalRecordLockOwner> {
        self.waiting_on
            .values()
            .find(|(waiter, _)| *waiter == owner)
            .map(|(_, blocker)| *blocker)
    }
}

#[derive(Default)]
pub(crate) struct LogicalRecordLocks {
    pub(crate) state: parking_lot::Mutex<LogicalRecordLockState>,
    changed: parking_lot::Condvar,
    next_wait_id: std::sync::atomic::AtomicU64,
    /// How many entries the table holds right now — locks, flocks and
    /// published wait edges together — republished by
    /// [`LockedRecordLockState`] every time the mutex is released.
    ///
    /// It exists so a close can ask "could this table have anything to release?"
    /// BEFORE computing the file's identity. Identity for a `--fs host`
    /// description is `fstat(2)` on the backing descriptor, so asking the table
    /// first cost one host syscall on every guest `close` — measured
    /// 20,000/20,000 on the `openclose` reducer — for a table that is empty in
    /// every process that never calls `fcntl(F_SETLK)`/`flock`.
    ///
    /// The count is a property of the GUARD, not of any call site: the state is
    /// unreachable except through [`LogicalRecordLocks::state`], whose guard
    /// republishes on `Drop` and across a condvar wait, so a mutation path
    /// added later cannot forget to maintain it.
    occupancy: std::sync::atomic::AtomicUsize,
}

/// Exclusive access to [`LogicalRecordLockState`] that keeps
/// [`LogicalRecordLocks::occupancy`] true. Never hand out the inner
/// `MutexGuard`: releasing the mutex without republishing is exactly the drift
/// this type exists to make unrepresentable.
pub(crate) struct LockedRecordLockState<'a> {
    state: parking_lot::MutexGuard<'a, LogicalRecordLockState>,
    occupancy: &'a std::sync::atomic::AtomicUsize,
}

impl LockedRecordLockState<'_> {
    fn publish(&self) {
        let total = self
            .state
            .locks
            .len()
            .saturating_add(self.state.flocks.len())
            .saturating_add(self.state.waiting_on.len());
        self.occupancy
            .store(total, std::sync::atomic::Ordering::Release);
    }

    /// Wait on `changed`, releasing the mutex for the duration.
    ///
    /// The occupancy is republished BEFORE the mutex is released — a waiter
    /// that has already mutated the table must not leave it advertising itself
    /// as emptier than it is — and again once the wait re-acquires.
    fn wait_for(&mut self, changed: &parking_lot::Condvar, timeout: std::time::Duration) {
        self.publish();
        changed.wait_for(&mut self.state, timeout);
        self.publish();
    }
}

impl std::ops::Deref for LockedRecordLockState<'_> {
    type Target = LogicalRecordLockState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl std::ops::DerefMut for LockedRecordLockState<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl Drop for LockedRecordLockState<'_> {
    fn drop(&mut self) {
        self.publish();
    }
}

impl LogicalRecordLocks {
    /// The one way to reach the lock set. See [`LockedRecordLockState`].
    pub(crate) fn state(&self) -> LockedRecordLockState<'_> {
        LockedRecordLockState {
            state: self.state.lock(),
            occupancy: &self.occupancy,
        }
    }

    /// True iff the table holds no lock, no flock and no published wait edge,
    /// so nothing any owner could release lives in it and nobody can be parked
    /// on `changed` (both wait loops only park while a conflicting entry is
    /// present). Answering from the published count takes no mutex and, at a
    /// close, no file identity.
    pub(crate) fn is_empty(&self) -> bool {
        self.occupancy.load(std::sync::atomic::Ordering::Acquire) == 0
    }

    fn conflict_locked(
        locks: &[LogicalRecordLock],
        request: &LogicalRecordLockRequest,
    ) -> Option<LogicalRecordLock> {
        locks
            .iter()
            .filter(|lock| {
                lock.file == request.file
                    && lock.owner.conflicts_with(&request.owner)
                    && lock.range.overlaps(request.range)
                    && (lock.write || request.write)
            })
            .min_by_key(|lock| lock.range.start)
            .cloned()
    }

    fn replace_owner_range(
        locks: &mut Vec<LogicalRecordLock>,
        file: &LeaseFileId,
        owner: LogicalRecordLockOwner,
        range: LogicalRecordLockRange,
    ) {
        let mut retained = Vec::with_capacity(locks.len() + 2);
        for lock in locks.drain(..) {
            if &lock.file != file || lock.owner != owner || !lock.range.overlaps(range) {
                retained.push(lock);
                continue;
            }
            if lock.range.start < range.start {
                let mut prefix = lock.clone();
                prefix.range.end = range.start;
                retained.push(prefix);
            }
            if range.end < lock.range.end {
                let mut suffix = lock;
                suffix.range.start = range.end;
                retained.push(suffix);
            }
        }
        *locks = retained;
    }

    pub(crate) fn try_set(&self, request: LogicalRecordLockRequest) -> Result<(), LinuxErrno> {
        let mut state = self.state();
        if Self::conflict_locked(&state.locks, &request).is_some() {
            return Err(LINUX_EAGAIN);
        }
        Self::replace_owner_range(
            &mut state.locks,
            &request.file,
            request.owner,
            request.range,
        );
        state.locks.push(LogicalRecordLock {
            file: request.file,
            owner: request.owner,
            range: request.range,
            write: request.write,
        });
        self.changed.notify_all();
        Ok(())
    }

    pub(crate) fn unlock(
        &self,
        file: &LeaseFileId,
        owner: LogicalRecordLockOwner,
        range: LogicalRecordLockRange,
    ) {
        let mut state = self.state();
        Self::replace_owner_range(&mut state.locks, file, owner, range);
        self.changed.notify_all();
    }

    pub(crate) fn conflict(&self, request: &LogicalRecordLockRequest) -> Option<LogicalRecordLock> {
        Self::conflict_locked(&self.state().locks, request)
    }

    pub(crate) fn release_file_owner(&self, file: &LeaseFileId, owner: LogicalRecordLockOwner) {
        let mut state = self.state();
        state
            .locks
            .retain(|lock| lock.file != *file || lock.owner != owner);
        self.changed.notify_all();
    }

    pub(crate) fn release_owner(&self, owner: crate::kernel::TaskKey) {
        let owner = LogicalRecordLockOwner::from(owner);
        let mut state = self.state();
        state.locks.retain(|lock| lock.owner != owner);
        self.changed.notify_all();
    }

    pub(crate) fn try_flock(
        &self,
        file: LeaseFileId,
        owner: usize,
        write: bool,
    ) -> Result<(), LinuxErrno> {
        let mut state = self.state();
        let conflict = state
            .flocks
            .iter()
            .any(|lock| lock.file == file && lock.owner != owner && (lock.write || write));
        if conflict {
            return Err(LINUX_EAGAIN);
        }
        state
            .flocks
            .retain(|lock| lock.file != file || lock.owner != owner);
        state.flocks.push(LogicalFlock { file, owner, write });
        self.changed.notify_all();
        Ok(())
    }

    pub(crate) fn unlock_flock(&self, file: &LeaseFileId, owner: usize) {
        let mut state = self.state();
        state
            .flocks
            .retain(|lock| lock.file != *file || lock.owner != owner);
        self.changed.notify_all();
    }

    pub(crate) fn wait_flock_interruptibly(
        &self,
        file: &LeaseFileId,
        owner: usize,
        write: bool,
        tid: crate::thread::ThreadId,
    ) -> Result<(), LinuxErrno> {
        let mut state = self.state();
        loop {
            let conflict = state
                .flocks
                .iter()
                .any(|lock| lock.file == *file && lock.owner != owner && (lock.write || write));
            if !conflict {
                state
                    .flocks
                    .retain(|lock| lock.file != *file || lock.owner != owner);
                state.flocks.push(LogicalFlock {
                    file: file.clone(),
                    owner,
                    write,
                });
                self.changed.notify_all();
                return Ok(());
            }
            if crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                carrick_abi::SigBlockMask::NONE,
            ) {
                return Err(LINUX_EINTR);
            }
            state.wait_for(&self.changed, std::time::Duration::from_millis(10));
        }
    }

    pub(crate) fn release_ofd(&self, file: &LeaseFileId, owner: usize) {
        let mut state = self.state();
        state
            .locks
            .retain(|lock| lock.file != *file || lock.owner != LogicalRecordLockOwner::Ofd(owner));
        state
            .flocks
            .retain(|lock| lock.file != *file || lock.owner != owner);
        self.changed.notify_all();
    }

    /// Would `me` blocking on `blocker` close a cycle in the wait-for graph?
    ///
    /// fcntl(2): "EDEADLK — It was detected that the specified F_SETLKW command
    /// would cause a deadlock." Linux walks the wait-for graph over blocked
    /// POSIX-lock waiters; so do we. Search every chain from the owner that
    /// would block us: if any leads back to us, waiting would deadlock. An
    /// owner can have several outgoing edges (one per blocked thread), so
    /// this is a depth-first search with a visited set, not a single-hop walk.
    fn would_deadlock(
        state: &LogicalRecordLockState,
        me: LogicalRecordLockOwner,
        blocker: LogicalRecordLockOwner,
    ) -> bool {
        let mut visited = std::collections::HashSet::new();
        let mut frontier = vec![blocker];
        while let Some(owner) = frontier.pop() {
            if owner == me {
                return true;
            }
            if !visited.insert(owner) {
                continue;
            }
            frontier.extend(
                state
                    .waiting_on
                    .values()
                    .filter(|(waiter, _)| *waiter == owner)
                    .map(|(_, next)| *next),
            );
        }
        false
    }

    fn mint_wait_id(&self) -> RecordLockWaitId {
        RecordLockWaitId(
            self.next_wait_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Remove `wait`'s edge. A retracted edge can flip somebody else's
    /// deadlock verdict, so anyone parked is woken to re-evaluate.
    fn retract_wait_locked(&self, state: &mut LogicalRecordLockState, wait: RecordLockWaitId) {
        if state.waiting_on.remove(&wait).is_some() {
            self.changed.notify_all();
        }
    }

    fn retract_wait(&self, wait: RecordLockWaitId) {
        let mut state = self.state();
        self.retract_wait_locked(&mut state, wait);
    }

    /// One step of a blocking `F_SETLKW`: THE primitive that maintains the
    /// wait-for graph. Both the thread-parking path and the reactor's
    /// re-poll go through here, so `EDEADLK` is reachable from either.
    ///
    /// - no conflict → the lock is taken, the wait's edge retracted, `Ok`;
    /// - a POSIX-owner cycle → the edge is retracted, `EDEADLK`;
    /// - otherwise the edge `wait: owner → blocker` is published (refreshed
    ///   each step, since the owner blocking us changes as locks move) and
    ///   the caller gets `EAGAIN`, meaning "still blocked, keep waiting".
    fn poll_set_locked(
        &self,
        state: &mut LogicalRecordLockState,
        request: &LogicalRecordLockRequest,
        wait: RecordLockWaitId,
    ) -> Result<(), LinuxErrno> {
        let Some(blocker) = Self::conflict_locked(&state.locks, request) else {
            Self::replace_owner_range(
                &mut state.locks,
                &request.file,
                request.owner,
                request.range,
            );
            state.locks.push(LogicalRecordLock {
                file: request.file.clone(),
                owner: request.owner,
                range: request.range,
                write: request.write,
            });
            state.waiting_on.remove(&wait);
            self.changed.notify_all();
            return Ok(());
        };
        if let (LogicalRecordLockOwner::Process { .. }, LogicalRecordLockOwner::Process { .. }) =
            (request.owner, blocker.owner)
        {
            if Self::would_deadlock(state, request.owner, blocker.owner) {
                self.retract_wait_locked(state, wait);
                return Err(crate::linux_abi::LINUX_EDEADLK);
            }
        }
        state
            .waiting_on
            .insert(wait, (request.owner, blocker.owner));
        Err(LINUX_EAGAIN)
    }

    pub(crate) fn wait_set_interruptibly(
        &self,
        request: &LogicalRecordLockRequest,
        tid: crate::thread::ThreadId,
    ) -> Result<(), LinuxErrno> {
        let wait = self.mint_wait_id();
        let mut state = self.state();
        loop {
            match self.poll_set_locked(&mut state, request, wait) {
                Err(errno) if errno == LINUX_EAGAIN => {}
                settled => break settled,
            }
            if crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                carrick_abi::SigBlockMask::NONE,
            ) {
                self.retract_wait_locked(&mut state, wait);
                break Err(LINUX_EINTR);
            }
            state.wait_for(&self.changed, std::time::Duration::from_millis(10));
        }
    }
}

/// The wait-for edge a `LogicalRecordLockWait` may hold, retracted when the
/// last clone of the wait is dropped. The reactor clones its continuation
/// freely; only the death of the whole wait means "no longer blocked".
struct RecordLockWaitEdge {
    locks: Arc<LogicalRecordLocks>,
    id: RecordLockWaitId,
}

impl Drop for RecordLockWaitEdge {
    fn drop(&mut self) {
        self.locks.retract_wait(self.id);
    }
}

#[derive(Clone)]
pub(crate) struct LogicalRecordLockWait {
    locks: Arc<LogicalRecordLocks>,
    request: LogicalRecordLockRequest,
    tid: crate::thread::ThreadId,
    edge: Arc<RecordLockWaitEdge>,
}

impl LogicalRecordLockWait {
    pub(crate) fn new(
        locks: Arc<LogicalRecordLocks>,
        request: LogicalRecordLockRequest,
        tid: crate::thread::ThreadId,
    ) -> Self {
        let edge = Arc::new(RecordLockWaitEdge {
            locks: Arc::clone(&locks),
            id: locks.mint_wait_id(),
        });
        Self {
            locks,
            request,
            tid,
            edge,
        }
    }

    /// Park the calling host thread until the lock is taken, `EDEADLK`, or a
    /// pending signal (`EINTR`).
    pub(crate) fn acquire(&self) -> Result<(), LinuxErrno> {
        self.locks.wait_set_interruptibly(&self.request, self.tid)
    }

    /// One reactor step: take the lock if it is free, `EDEADLK` if waiting
    /// would close a cycle, `EAGAIN` while still blocked. Unlike `F_SETLK`'s
    /// `try_set`, this publishes the wait's edge in the wait-for graph so the
    /// deadlock a re-polled waiter is part of is visible to the other side.
    pub(crate) fn try_acquire(&self) -> Result<(), LinuxErrno> {
        let mut state = self.locks.state.lock();
        self.locks
            .poll_set_locked(&mut state, &self.request, self.edge.id)
    }
}

#[cfg(test)]
pub(crate) struct RecordLockContentionFixture {
    locks: Arc<LogicalRecordLocks>,
    file: LeaseFileId,
    range: LogicalRecordLockRange,
    blocker: LogicalRecordLockOwner,
}

#[cfg(test)]
impl RecordLockContentionFixture {
    pub(crate) fn new() -> Self {
        let locks = Arc::new(LogicalRecordLocks::default());
        let file = LeaseFileId::Path("task5-record-lock".to_owned());
        let range = LogicalRecordLockRange { start: 0, end: 1 };
        let blocker = LogicalRecordLockOwner::Process { pid: 41, serial: 1 };
        locks
            .try_set(LogicalRecordLockRequest {
                file: file.clone(),
                owner: blocker,
                range,
                write: true,
            })
            .expect("seed blocking record lock");
        Self {
            locks,
            file,
            range,
            blocker,
        }
    }

    pub(crate) fn waiter(
        &self,
        tid: crate::thread::ThreadId,
        serial: u64,
    ) -> crate::dispatch::BlockingRecordLock {
        crate::dispatch::BlockingRecordLock::logical(LogicalRecordLockWait::new(
            Arc::clone(&self.locks),
            LogicalRecordLockRequest {
                file: self.file.clone(),
                owner: LogicalRecordLockOwner::Process {
                    pid: i32::try_from(serial).unwrap_or(i32::MAX),
                    serial,
                },
                range: self.range,
                write: true,
            },
            tid,
        ))
    }

    pub(crate) fn release_blocker(&self) {
        self.locks.unlock(&self.file, self.blocker, self.range);
    }
}

impl PartialEq for LogicalRecordLockWait {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.locks, &other.locks)
            && self.request == other.request
            && self.tid == other.tid
    }
}

impl Eq for LogicalRecordLockWait {}

impl std::fmt::Debug for LogicalRecordLockWait {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogicalRecordLockWait")
            .field("request", &self.request)
            .field("tid", &self.tid)
            .finish_non_exhaustive()
    }
}

fn logical_record_lock_file(host_fd: i32) -> Result<LeaseFileId, LinuxErrno> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(host_fd, &mut stat) }.host_syscall_errno()?;
    Ok(LeaseFileId::Inode {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    })
}

fn normalize_logical_record_lock_range(
    host_fd: i32,
    whence: i16,
    start: i64,
    len: i64,
) -> Result<LogicalRecordLockRange, LinuxErrno> {
    let origin = match i32::from(whence) {
        libc::SEEK_SET => 0_i128,
        libc::SEEK_CUR => {
            let offset = unsafe { libc::lseek(host_fd, 0, libc::SEEK_CUR) };
            if offset < 0 {
                return Err(crate::host_to_linux_errno(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL),
                ));
            }
            i128::from(offset)
        }
        libc::SEEK_END => {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::fstat(host_fd, &mut stat) }.host_syscall_errno()?;
            i128::from(stat.st_size)
        }
        _ => return Err(LINUX_EINVAL),
    };
    let anchor = origin.checked_add(i128::from(start)).ok_or(LINUX_EINVAL)?;
    let (range_start, range_end) = match len.cmp(&0) {
        std::cmp::Ordering::Greater => (
            anchor,
            anchor.checked_add(i128::from(len)).ok_or(LINUX_EINVAL)?,
        ),
        std::cmp::Ordering::Equal => (anchor, i128::from(i64::MAX) + 1),
        std::cmp::Ordering::Less => (
            anchor.checked_add(i128::from(len)).ok_or(LINUX_EINVAL)?,
            anchor,
        ),
    };
    if range_start < 0 || range_end <= range_start || range_end > i128::from(i64::MAX) + 1 {
        return Err(LINUX_EINVAL);
    }
    Ok(LogicalRecordLockRange {
        start: u64::try_from(range_start).map_err(|_| LINUX_EINVAL)?,
        end: u64::try_from(range_end).map_err(|_| LINUX_EINVAL)?,
    })
}

fn write_logical_record_lock_conflict(
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    arg: u64,
    conflict: Option<LogicalRecordLock>,
    is_ofd: bool,
) -> DispatchOutcome {
    let Some(conflict) = conflict else {
        return if memory
            .write_bytes(arg, &(LINUX_F_UNLCK as i16).to_le_bytes())
            .is_ok()
        {
            DispatchOutcome::Returned { value: 0 }
        } else {
            DispatchOutcome::errno(LINUX_EFAULT)
        };
    };
    let mut out = [0_u8; 32];
    let lock_type = if conflict.write {
        LINUX_F_WRLCK
    } else {
        LINUX_F_RDLCK
    } as i16;
    let len = if conflict.range.end == i64::MAX as u64 + 1 {
        0_i64
    } else {
        i64::try_from(conflict.range.end.saturating_sub(conflict.range.start)).unwrap_or(i64::MAX)
    };
    let pid = if is_ofd {
        -1
    } else {
        conflict
            .owner
            .task_key()
            .filter(|key| context.kernel().task_key_is_live(*key))
            .and_then(|key| u32::try_from(key.id.raw()).ok())
            .and_then(|pid| crate::namespace::pid::kernel_to_ns_for(context, pid))
            .and_then(|pid| i32::try_from(pid).ok())
            .unwrap_or(0)
    };
    out[0..2].copy_from_slice(&lock_type.to_le_bytes());
    out[2..4].copy_from_slice(&(libc::SEEK_SET as i16).to_le_bytes());
    out[8..16].copy_from_slice(&(conflict.range.start as i64).to_le_bytes());
    out[16..24].copy_from_slice(&len.to_le_bytes());
    out[24..28].copy_from_slice(&pid.to_le_bytes());
    if memory.write_bytes(arg, &out).is_err() {
        DispatchOutcome::errno(LINUX_EFAULT)
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

impl SyscallDispatcher {
    /// Access modes (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) of every OTHER open file
    /// description that refers to the SAME underlying file as `fd` — i.e. a
    /// distinct `open(2)` of the same inode, not a `dup(2)` (which shares the
    /// description, identified by `Arc` pointer identity). Used by F_SETLEASE to
    /// enforce Linux's lease-conflict rules: "a write lease may be placed on a
    /// file only if there are no other open file descriptors for the file".
    ///
    /// Same-file identity is the host inode under `--fs host` (`fstat` dev+ino on
    /// the HostFile's kernel fd, which is fork-coherent), falling back to the
    /// guest open-path for the in-memory `File` backing. Descriptions that are
    /// not regular files (pipes/sockets/anon-inodes) never share inode identity
    /// with a regular-file lease target and are skipped.
    fn same_file_other_openers(&self, fd: i32) -> Vec<u64> {
        let Some(target) = self.open_file(fd) else {
            return Vec::new();
        };
        let target_id = {
            target
                .description
                .read()
                .and_then(|desc| Self::lease_file_identity(&desc))
        };
        let Some(target_id) = target_id else {
            return Vec::new();
        };
        let mut others = Vec::new();
        for (other_fd, open_file) in self.captured_file_table().read_open_files().iter() {
            if *other_fd == fd {
                continue;
            }
            // A `dup(2)`/inherited fd shares the same description `Arc`; it is the
            // same open file description, not a separate opener, so it does not
            // conflict.
            if Arc::ptr_eq(&open_file.description, &target.description) {
                continue;
            }
            if let Some(desc) = open_file.description.read()
                && Self::lease_file_identity(&desc).as_ref() == Some(&target_id)
            {
                others.push(open_file.description.common().status_flags() & LINUX_O_ACCMODE);
            }
        }
        others
    }

    /// Inode-level identity used to decide whether two open descriptions name the
    /// same file for lease-conflict accounting. `None` for descriptions that
    /// cannot be a lease target's peer (pipes, sockets, anon-inodes).
    pub(in crate::dispatch) fn lease_file_identity(desc: &OpenDescription) -> Option<LeaseFileId> {
        match desc {
            OpenDescription::HostFile { host_fd, .. } => {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0 {
                    Some(LeaseFileId::Inode {
                        dev: st.st_dev as u64,
                        ino: st.st_ino as u64,
                    })
                } else {
                    None
                }
            }
            OpenDescription::File { path, .. } => Some(LeaseFileId::Path(path.clone())),
            _ => None,
        }
    }

    pub(in crate::dispatch) fn release_hvpatch_classic_record_locks(
        &self,
        owner: crate::kernel::TaskKey,
        open_file: &OpenFile,
    ) {
        // Ask the TABLE before asking the FILE. Keying the release needs the
        // description's identity, and for a `--fs host` description that is
        // `fstat(2)` on the backing descriptor — a host syscall this path used
        // to pay on every guest `close` (`hvpatch-syscall-host-tax.d` on the
        // `openclose` reducer: 20,000 host `fstat64` for 20,000 closes) purely
        // to look up a table that is empty in every process which never took a
        // record lock. An empty table has nothing to release and, because both
        // wait loops only park while a conflicting entry is present, no waiter
        // to notify either.
        if self.fs.classic_record_locks.is_empty() {
            return;
        }
        let file = {
            open_file
                .description
                .read()
                .and_then(|description| Self::lease_file_identity(&description))
        };
        if let Some(file) = file {
            self.fs
                .classic_record_locks
                .release_file_owner(&file, LogicalRecordLockOwner::from(owner));
            let is_last_ref = Arc::strong_count(&open_file.description) <= 2;
            if is_last_ref {
                let desc_ptr = Arc::as_ptr(&open_file.description) as usize;
                self.fs.classic_record_locks.release_ofd(&file, desc_ptr);
            }
        }
    }

    /// Reconcile the carrier-coherent FASYNC registry with `fd`'s current
    /// description after an `O_ASYNC` / `F_SETOWN` / `F_SETSIG` change. If
    /// `O_ASYNC` is set on a host pipe/socket, arm `(dev, ino)` with the fd's
    /// exact owner generation + signal so a writer in another guest task can
    /// deliver the I/O signal on the readiness edge; if `O_ASYNC` is clear,
    /// disarm it. A no-op
    /// for non-pipe/socket fds (FASYNC delivery is only wired for the
    /// pipe/socket readiness edge carrick can observe).
    pub(in crate::dispatch) fn sync_fasync_registration(&self, fd: i32) {
        let Some(pipe_id) = self.host_pipe_pipe_id(fd) else {
            return;
        };
        let Some(open_file) = self.open_file(fd) else {
            return;
        };
        let common = open_file.description.common();
        let armed = LinuxOpenFlags::from_bits_truncate(common.status_flags())
            .contains(LinuxOpenFlags::ASYNC);
        if !armed {
            carrick_signal_core::fasync::disarm(pipe_id, open_file.description.id().raw());
            return;
        }
        let owner = common.captured_owner();
        let (owner_type, owner_pid) = (owner.visible.owner_type, owner.visible.owner_pid);
        let sig = common.async_sig();
        carrick_signal_core::fasync::arm(
            pipe_id,
            carrick_signal_core::fasync::FasyncOwner {
                registration_id: open_file.description.id().raw(),
                owner_pid,
                owner_type,
                sig,
                container_id: owner.target.container_id,
                target_id: owner.target.target_id,
                target_generation: owner.target.target_generation,
                thread_id: owner.target.thread_id,
                thread_generation: owner.target.thread_generation,
            },
        );
    }

    pub(in crate::dispatch) fn send_async_owner_signal(
        &self,
        context: &crate::kernel::KernelContext,
        owner: crate::kernel::objects::CapturedAsyncIoOwner,
        sig: i32,
        fd: i32,
    ) {
        if owner.visible.owner_pid == 0 {
            return;
        }
        let signum = if sig == 0 { LINUX_SIGIO } else { sig };
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return;
        };
        let info = carrick_abi::LinuxSiginfo::sigpoll(signum, carrick_abi::LINUX_POLL_MSG, 0, fd);
        // This is a kernel-owned readiness notification, not a guest kill(2):
        // route it through the exact task/thread/group generation captured by
        // F_SETOWN. The event-producing context may belong to another process
        // or container and is deliberately not used as target authority.
        let _ = owner.post_kernel_signal(context.kernel(), signal, Some(info));
    }

    /// Deliver the FASYNC (signal-driven I/O) signal after a guest write to a
    /// host pipe/socket made it readable. Looks up the pipe inode in the
    /// carrier-coherent registry; if armed, posts the owner's `F_SETSIG` signal
    /// (default `SIGIO`) through Carrick's exact-generation signal authority.
    /// This is the readiness EDGE the writer can observe: a write that
    /// added bytes transitions the reader's fd to readable, which is exactly when
    /// Linux raises the owner's I/O signal. (`written <= 0` — a short/blocked
    /// write that added nothing — is not an edge and delivers nothing.)
    pub(in crate::dispatch) fn fasync_notify_after_write(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        written: i64,
    ) {
        if written <= 0 {
            return;
        }
        // Hot path: skip the per-write inode fstat entirely unless some fd
        // somewhere is armed for signal-driven I/O (the common case is none).
        if !carrick_signal_core::fasync::any_armed() {
            return;
        }
        let Some(pipe_id) = self.host_pipe_pipe_id(fd) else {
            return;
        };
        let Some(owner) = carrick_signal_core::fasync::lookup(pipe_id) else {
            return;
        };
        let sig = owner.sig;
        let owner = crate::kernel::objects::CapturedAsyncIoOwner {
            visible: crate::kernel::objects::AsyncIoOwner {
                owner_pid: owner.owner_pid,
                owner_type: owner.owner_type,
            },
            target: crate::kernel::objects::AsyncIoTarget {
                container_id: owner.container_id,
                target_id: owner.target_id,
                target_generation: owner.target_generation,
                thread_id: owner.thread_id,
                thread_generation: owner.thread_generation,
            },
        };
        self.send_async_owner_signal(context, owner, sig, fd);
    }

    /// Pipe-identity token used to coordinate FASYNC readiness between reader
    /// and writer descriptors. For a `HostPipe` this is the synthetic
    /// allocation-time `pipe_id` carried in its description (authoritative on
    /// macOS, where a pipe's two ends have different `st_ino`). For a
    /// `HostSocket` there is no creation-time shared id, so the socket's host
    /// inode is used (the existing socket-fasync behaviour). `None` for
    /// non-pipe/socket fds, a `pipe_id` of `0` (no real pipe object), or a failed
    /// socket fstat.
    pub(in crate::dispatch) fn host_pipe_pipe_id(&self, fd: i32) -> Option<u64> {
        let open_file = self.open_file(fd)?;
        self.fasync_pipe_id_for_open_file(&open_file)
    }

    pub(in crate::dispatch) fn fasync_pipe_id_for_open_file(
        &self,
        open_file: &OpenFile,
    ) -> Option<u64> {
        let open = open_file.description.read()?;
        let host_socket_fd = match &*open {
            OpenDescription::PipeReader { pipe, .. } | OpenDescription::PipeWriter { pipe, .. } => {
                return Some(pipe.pipe_id());
            }
            OpenDescription::HostPipe { pipe_id, .. } => {
                return (*pipe_id != 0).then_some(*pipe_id);
            }
            OpenDescription::HostSocket { host_fd, .. } => host_fd.raw(),
            _ => return None,
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(host_socket_fd, &mut st) } != 0 {
            return None;
        }
        let ino = st.st_ino as u64;
        (ino != 0).then_some(ino)
    }

    define_syscall! {
        mm_mutation fn fcntl(this, cx, fd: Fd, cmd: u64, arg: u64) {
            let fd: Fd = fd;
            let command = cmd;
            // A stdio fd the guest explicitly closed (and did not reopen) is a
            // genuinely closed descriptor: every fcntl on it is EBADF, NOT the
            // implicit-stdio fallbacks below (F_GETFL/F_GETFD/F_SETFL on bare
            // stdio). CPython's init_sys_streams uses fcntl(F_GETFL) to size up
            // each std fd at startup and treats EBADF as "stream is closed →
            // sys.stdin/out/err = None" (test_cmd_line.test_no_std*).
            if this.stdio_is_closed(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            Ok(match command {
                LINUX_F_DUPFD => match linux_min_fd(arg) {
                    Ok(min_fd) => this.duplicate_fd(fd.0, min_fd, 0),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_F_DUPFD_CLOEXEC => match linux_min_fd(arg) {
                    Ok(min_fd) => this.duplicate_fd(fd.0, min_fd, LINUX_FD_CLOEXEC),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_F_GETPIPE_SZ => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let Some(open) = open_file.description.read() else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    match &*open {
                        OpenDescription::PipeReader { pipe, .. }
                        | OpenDescription::PipeWriter { pipe, .. } => {
                            DispatchOutcome::returned_len_or_errno(pipe.get_capacity())
                        }
                        OpenDescription::HostPipe { base, .. } => DispatchOutcome::Returned {
                            // The per-description capacity, set by a prior
                            // F_SETPIPE_SZ or the default pipe buffer size.
                            value: base.pipe_capacity(),
                        },
                        OpenDescription::HostSocket { .. } => DispatchOutcome::errno(LINUX_EBADF),
                        _ => DispatchOutcome::errno(LINUX_EBADF),
                    }
                }
                LINUX_F_SETPIPE_SZ => {
                    let table = this.captured_file_table();
                    let Ok(slot_num) = crate::kernel::FileSlotNumber::for_open_fd(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let Some(slot) = table.capture_slot_authority(slot_num) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };

                    let accounting = {
                        let Some(open_file) = this.open_file(fd.0) else {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        };
                        let Some(open) = open_file.description.read() else {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        };
                        match &*open {
                            OpenDescription::PipeReader { .. }
                            | OpenDescription::PipeWriter { .. } => {
                                crate::kernel::objects::PipeCapacityAccounting::InMemory
                            }
                            OpenDescription::HostPipe {
                                base,
                                pipe_id,
                                is_read_end,
                                bidirectional,
                                host_fd,
                                ..
                            } => {
                                let Some((_, queued)) = this.host_pipe_capacity_state(
                                    base,
                                    *pipe_id,
                                    *is_read_end,
                                    *bidirectional,
                                    host_fd.raw(),
                                ) else {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                };
                                let queued_with_staged =
                                    queued + this.staged_splice_pipe_bytes(fd.0);
                                crate::kernel::objects::PipeCapacityAccounting::Host {
                                    queued_bytes: queued_with_staged as u64,
                                }
                            }
                            _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                        }
                    };

                    const PIPE_MAX_SIZE: u64 = 1 << 20; // 1 MiB, Linux default
                    if arg > i32::MAX as u64 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let page = LINUX_PAGE_SIZE;
                    let requested = arg.max(1);
                    let rounded = requested.div_ceil(page).saturating_mul(page);
                    if rounded > PIPE_MAX_SIZE {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    let capacity = match crate::file_authority::PipeCapacity::bounded(
                        rounded.max(page) as u32,
                    ) {
                        Ok(cap) => cap,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    };

                    let command = crate::file_authority::Command::SetCanonicalPipeCapacity {
                        slot,
                        capacity,
                        accounting,
                    };

                    match this.authority_call(table, slot, command) {
                        Ok(crate::file_authority::Outcome::CanonicalPipeCapacitySet {
                            capacity,
                            ..
                        }) => DispatchOutcome::returned_u32(capacity.raw()),
                        Ok(_) => {
                            return Err(DispatchError::FileAuthorityFatal(
                                crate::file_authority::AuthorityFatal::InvariantViolation(
                                    "unexpected outcome for SetCanonicalPipeCapacity",
                                ),
                            ));
                        }
                        Err(AuthorityCallError::Rejected(
                            crate::file_authority::AuthorityError::InvalidPipeCapacity,
                        )) => DispatchOutcome::errno(LINUX_EINVAL),
                        Err(AuthorityCallError::Rejected(
                            crate::file_authority::AuthorityError::PipeErrno(errno),
                        )) => DispatchOutcome::errno(errno),
                        Err(AuthorityCallError::Rejected(
                            crate::file_authority::AuthorityError::NotPipe
                            | crate::file_authority::AuthorityError::StaleSlot { .. }
                            | crate::file_authority::AuthorityError::SlotNotFound
                            | crate::file_authority::AuthorityError::TableNotFound
                            | crate::file_authority::AuthorityError::DescriptionNotFound
                            | crate::file_authority::AuthorityError::TableNotBound,
                        )) => DispatchOutcome::errno(LINUX_EBADF),
                        Err(AuthorityCallError::Rejected(_)) => {
                            return Err(DispatchError::FileAuthorityFatal(
                                crate::file_authority::AuthorityFatal::InvariantViolation(
                                    "unexpected authority rejection for SetCanonicalPipeCapacity",
                                ),
                            ));
                        }
                        Err(AuthorityCallError::Fatal(fatal)) => {
                            return Err(DispatchError::FileAuthorityFatal(fatal));
                        }
                    }
                }
                // Directory-change notification (dnotify). It is obsolete, but
                // LTP still asserts create/delete/rename SIGIO delivery for
                // aarch64. Record a dispatch-layer directory watch and reuse the
                // fd's F_SETOWN/F_SETSIG async owner for signal delivery.
                LINUX_F_NOTIFY => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let Some(mask) = LinuxDnotifyMask::from_bits(arg) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    if let Err(errno) = this.dnotify_register(cx.kernel, fd.0, mask, cx.tid()) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETFD => {
                    if let Some(open_file) = this.open_file(fd.0) {
                        return Ok(DispatchOutcome::returned_u64_or_errno(open_file.fd_flags));
                    }
                    // stdio without an OpenDescription: stdio is not CLOEXEC by
                    // default (Linux: stdio survives exec), but a prior
                    // F_SETFD FD_CLOEXEC must be reflected back. Read the
                    // remembered per-stdio-fd bit.
                    if is_stdio_fd(fd.0) {
                        let bit = if this.captured_file_table().lock_stdio_cloexec()[fd.0 as usize] {
                            LINUX_FD_CLOEXEC as i64
                        } else {
                            0
                        };
                        return Ok(DispatchOutcome::Returned { value: bit });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_SETFD => {
                    let fd_flags = LinuxFdFlags::from_bits_truncate(arg);
                    if let Some(open_file) = this.captured_file_table().write_open_files().get_mut(&fd.0) {
                        open_file.fd_flags = fd_flags.bits();
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    // apt's http method fcntl(fd, F_SETFD, FD_CLOEXEC)s its
                    // inherited stdio fds on startup. Returning EBADF here
                    // makes apt abort with "Could not set close on exec".
                    // Carrick's exec inherits stdio via the host fd directly;
                    // CLOEXEC is largely cosmetic for our model (we don't exec
                    // anything host-side after the syscall returns) but we
                    // remember the bit so a subsequent F_GETFD reflects it,
                    // matching real Linux.
                    if is_stdio_fd(fd.0) {
                        this.captured_file_table().lock_stdio_cloexec()[fd.0 as usize] =
                            fd_flags.contains(LinuxFdFlags::CLOEXEC);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_GETFL => {
                    if let Some(open_file) = this.open_file(fd.0) {
                        // The guest's status flags are the answer. The host
                        // fd behind a regular file is carrick's business: it
                        // is O_NONBLOCK from open (the FIFO-never-blocks-the-
                        // dispatcher rule) whether or not the guest asked, and
                        // the write path mirrors guest O_APPEND onto it lazily
                        // — neither may leak into what the guest reads back
                        // (probe fileaccessmode: an O_RDONLY open reports
                        // exactly O_RDONLY|O_LARGEFILE, as Linux does).
                        let mut flags =
                            reportable_status_flags(open_file.description.common().status_flags());
                        if let Some(open) = open_file.description.read()
                            && matches!(&*open, OpenDescription::HostPipe { pty: Some(_), .. })
                        {
                            flags |= LINUX_O_RDWR;
                        }
                        return Ok(DispatchOutcome::returned_u64_or_errno(flags));
                    }
                    // stdio without an OpenDescription: glibc cat/head/etc
                    // probe `fcntl(1, F_GETFL)` on startup to decide whether
                    // stdout is append-only. Returning O_RDWR (with the
                    // appropriate direction for fd 0 vs 1/2) keeps them happy
                    // instead of bailing with "Bad file descriptor".
                    if is_stdio_fd(fd.0) {
                        let flags: u64 = if fd.0 == 0 {
                            LINUX_O_RDONLY
                        } else {
                            LINUX_O_WRONLY
                        };
                        return Ok(DispatchOutcome::returned_u64_or_errno(flags));
                    }
                    DispatchOutcome::errno(LINUX_EBADF)
                }
                LINUX_F_SETFL => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        // Bare stdio (0/1/2) has no OpenDescription, but real Linux
                        // lets you fcntl(F_SETFL) on stdin/stdout/stderr. apt's dpkg
                        // child sets stdin non-blocking via fcntl(0, F_SETFL,
                        // O_NONBLOCK) before exec and treats EBADF as fatal — it
                        // _exit(100)'d, failing `apt install` ("Sub-process dpkg
                        // returned an error code (100)"). Accept it, propagating
                        // O_NONBLOCK to the real host stdio fd when the guest's
                        // stdio is wired to our host fds (StdioSink::Inherit),
                        // mirroring the F_GETFD/F_SETFD/F_GETFL stdio special-cases.
                        if is_stdio_fd(fd.0) {
                            if this.io.inherits_host_stdio() {
                                let want_nonblock = arg & LINUX_O_NONBLOCK != 0;
                                unsafe {
                                    let cur = libc::fcntl(fd.0, libc::F_GETFL, 0);
                                    if cur >= 0 {
                                        let next = if want_nonblock {
                                            cur | libc::O_NONBLOCK
                                        } else {
                                            cur & !libc::O_NONBLOCK
                                        };
                                        if next != cur {
                                            libc::fcntl(fd.0, libc::F_SETFL, next);
                                        }
                                    }
                                }
                            }
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // Linux F_SETFL changes ONLY the mutable file-status flags;
                    // it cannot change the access mode (O_RDONLY/WRONLY/RDWR) and
                    // ignores creation-only bits (O_CREAT/O_EXCL/O_TRUNC) and
                    // O_CLOEXEC. Preserve the description's access mode and take
                    // only the mutable status bits from `arg`, so a later F_GETFL
                    // reports the Linux-correct combination instead of whatever
                    // junk the guest passed. (audit M4; probe fsetfl)
                    // O_APPEND + O_NONBLOCK + O_ASYNC are the mutable status bits a
                    // guest realistically toggles via F_SETFL (O_DIRECT/O_NOATIME
                    // are still ignored). O_ASYNC enables signal-driven I/O (the
                    // kernel signals the F_SETOWN owner on a readiness edge).
                    const LINUX_F_SETFL_MUTABLE: u64 =
                        LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_ASYNC;
                    let Some(open) = open_file.description.read() else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let next_flags = (open_file.description.common().status_flags()
                        & LINUX_O_ACCMODE)
                        | (arg & LINUX_F_SETFL_MUTABLE);
                    // Regular host files delegate O_APPEND/O_NONBLOCK to the
                    // shared host open description, which is the only mutable
                    // state that remains coherent across a real host fork.
                    // Pipes/sockets stay host-nonblocking regardless of their
                    // Linux-visible flag so dispatcher operations cannot block
                    // while holding runtime locks.
                    match &*open {
                        OpenDescription::HostFile { host_fd, .. } => {
                            let current = match (unsafe {
                                libc::fcntl(host_fd.raw(), libc::F_GETFL, 0)
                            })
                            .host_syscall_errno()
                            {
                                Ok(value) => value,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            let mut next = current & !(libc::O_APPEND | libc::O_NONBLOCK);
                            if next_flags & LINUX_O_APPEND != 0 {
                                next |= libc::O_APPEND;
                            }
                            if next_flags & LINUX_O_NONBLOCK != 0 {
                                next |= libc::O_NONBLOCK;
                            }
                            if next != current
                                && let Err(errno) = (unsafe {
                                    libc::fcntl(host_fd.raw(), libc::F_SETFL, next)
                                })
                                .host_syscall_errno()
                            {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                        }
                        OpenDescription::HostPipe { host_fd, .. }
                        | OpenDescription::HostSocket { host_fd, .. } => {
                            crate::dispatch::net::set_host_nonblocking(host_fd.raw());
                        }
                        _ => {}
                    }
                    drop(open);
                    open_file.description.common().set_status_flags(next_flags);
                    // Reflect the new O_ASYNC state into the fork-coherent FASYNC
                    // registry so a WRITER in another guest process can deliver the
                    // owner's signal on the readiness edge (the arming lives on the
                    // reader's description, invisible to the writer process).
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                // Classic POSIX advisory record locks (F_SETLK/F_SETLKW/
                // F_GETLK). Forward to the host fd's REAL fcntl locking — macOS
                // implements byte-range advisory locks with conflict and
                // deadlock (EDEADLK) detection, and carrick's guest processes
                // are separate host processes sharing the host file, so the
                // host kernel gives correct cross-process conflict detection
                // for free (the Darwin-native path). The `struct flock` layout
                // AND the l_type constants differ between Linux and macOS, so
                // both are translated; `host_syscall_errno` maps the host errno
                // (incl. the EAGAIN/EDEADLK swap) back to Linux. Falls back to
                // the historical no-op success when the fd isn't host-backed
                // (in-memory/synthetic files, --fs memory) so apt's
                // /var/lib/apt/lists/lock path keeps working.
                LINUX_F_SETLK | LINUX_F_SETLKW => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let desc_ptr = this
                        .open_file(fd.0)
                        .map_or(0, |of| Arc::as_ptr(&of.description) as usize);
                    match this.host_file_fd_for_flush(fd.0) {
                        Ok(Some(host_fd)) => {
                            let tid = cx.tid();
                            forward_record_lock(
                                this,
                                RecordLockRequest {
                                    kernel: cx.kernel,
                                    memory: &mut *cx.memory,
                                    tid,
                                    host_fd,
                                    desc_ptr,
                                    linux_cmd: command,
                                    arg,
                                },
                            )
                        }
                        // Not host-backed → preserve the single-tenant no-op,
                        // but still do the kernel's front-door flock validation
                        // (EFAULT/EINVAL) that precedes the lock attempt.
                        Ok(None) => match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        },
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
                LINUX_F_GETLK => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let desc_ptr = this
                        .open_file(fd.0)
                        .map_or(0, |of| Arc::as_ptr(&of.description) as usize);
                    match this.host_file_fd_for_flush(fd.0) {
                        Ok(Some(host_fd)) => {
                            let tid = cx.tid();
                            forward_record_lock(
                                this,
                                RecordLockRequest {
                                    kernel: cx.kernel,
                                    memory: &mut *cx.memory,
                                    tid,
                                    host_fd,
                                    desc_ptr,
                                    linux_cmd: command,
                                    arg,
                                },
                            )
                        }
                        // Not host-backed → "no lock present": leave the
                        // caller's struct flock untouched (l_type=F_UNLCK is
                        // what callers re-read) and succeed — after the same
                        // front-door flock validation Linux applies first.
                        Ok(None) => match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        },
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
                // OFD locks (F_OFD_*) are owned by the open file description, not
                // the process.
                LINUX_F_OFD_SETLK | LINUX_F_OFD_SETLKW | LINUX_F_OFD_GETLK => {
                    if !this.fd_is_valid(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let desc_ptr = this
                        .open_file(fd.0)
                        .map_or(0, |of| Arc::as_ptr(&of.description) as usize);
                    match this.host_file_fd_for_flush(fd.0) {
                        Ok(Some(host_fd)) => {
                            let tid = cx.tid();
                            forward_record_lock(
                                this,
                                RecordLockRequest {
                                    kernel: cx.kernel,
                                    memory: &mut *cx.memory,
                                    tid,
                                    host_fd,
                                    desc_ptr,
                                    linux_cmd: command,
                                    arg,
                                },
                            )
                        }
                        Ok(None) => match validate_flock_arg(&*cx.memory, arg) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => DispatchOutcome::errno(errno),
                        },
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
                // File leases (F_SETLEASE/F_GETLEASE). macOS has no lease
                // primitive, so the lease type is recorded on the open-file
                // description (shared across dup). Conflict enforcement mirrors
                // fcntl(2): a WRITE lease (F_WRLCK) requires this to be the ONLY
                // open file description for the file; a READ lease (F_RDLCK)
                // requires no other description hold the file open for writing
                // (and that the calling fd itself be read-only). Conflicts return
                // EAGAIN. The opener census comes from `same_file_other_openers`
                // (host-inode identity under `--fs host`, path under `--fs
                // memory`); a dup'd fd shares the description and never conflicts.
                // Lease-break SIGIO delivery to a conflicting opener is a tracked
                // follow-up.
                LINUX_F_SETLEASE => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let lease = arg as i32;
                    if lease != LINUX_F_RDLCK
                        && lease != LINUX_F_WRLCK
                        && lease != LINUX_F_UNLCK
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let self_acc =
                        open_file.description.common().status_flags() & LINUX_O_ACCMODE;
                    match lease {
                        // A write lease demands exclusive access: any other open
                        // file description for the file is a conflict.
                        LINUX_F_WRLCK => {
                            if !this.same_file_other_openers(fd.0).is_empty() {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                        }
                        // A read lease forbids any writer. The calling fd must be
                        // read-only (an fd open for writing is itself a writer),
                        // and no other description may hold the file open for
                        // writing.
                        LINUX_F_RDLCK => {
                            if self_acc != LINUX_O_RDONLY {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                            let writer_exists = this
                                .same_file_other_openers(fd.0)
                                .into_iter()
                                .any(|acc| acc != LINUX_O_RDONLY);
                            if writer_exists {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                        }
                        // F_UNLCK: removing a lease never conflicts.
                        _ => {}
                    }
                    open_file.description.common().set_lease(lease);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETLEASE => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let lease = open_file.description.common().lease();
                    DispatchOutcome::returned_i32(lease)
                }
                // File sealing (memfd_create01). The seal set lives on the
                // open-file description (shared across dup). F_GET_SEALS returns
                // the current set; a non-sealable fd → EINVAL.
                LINUX_F_GET_SEALS => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    match open_file.description.common().seals() {
                        Some(seals) => DispatchOutcome::Returned {
                            value: i64::from(seals),
                        },
                        None => DispatchOutcome::errno(LINUX_EINVAL),
                    }
                }
                LINUX_F_ADD_SEALS => {
                    let Ok(new_seals_raw) = u32::try_from(arg) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let Some(new_seals) = carrick_abi::LinuxMemfdSeals::from_bits(new_seals_raw) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    // Hold the SAME alias-dispatch exclusion mmap/shmat use for
                    // publication, so a sibling cannot race between the seal
                    // check and the new seal becoming visible. Acquire it before
                    // any subsystem locks so we never wait while holding them.
                    let permit = cx.mm_mutation.host_alias_permit();
                    let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let common = open_file.description.common();
                    let Some(current_raw) = common.seals() else {
                        // Not a sealable fd (regular file, socket, …).
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let current = carrick_abi::LinuxMemfdSeals::from_bits_retain(current_raw);
                    // F_ADD_SEALS needs the fd open for writing.
                    if common.status_flags() & LINUX_O_ACCMODE == LINUX_O_RDONLY {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    // Already fully sealed → no further seals may be added.
                    if current.contains(carrick_abi::LinuxMemfdSeals::SEAL) {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    // F_SEAL_WRITE cannot be set while a shared, writable mapping
                    // of the memfd is live (Linux → EBUSY; memfd_create01
                    // test_share_mmap).
                    if new_seals.contains(carrick_abi::LinuxMemfdSeals::WRITE)
                        && this.memfd_has_writable_shared_map(&open_file.description)
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EBUSY));
                    }
                    common.set_seals(Some((current | new_seals).bits()));
                    DispatchOutcome::Returned { value: 0 }
                }
                // Async-I/O owner + signal (F_SETOWN/F_GETOWN, F_SETOWN_EX/
                // F_GETOWN_EX, F_SETSIG/F_GETSIG). The owner (SIGIO/SIGURG target)
                // and exact kernel target are recorded on the open-file
                // description (shared across dup), while the original visible
                // tuple remains the exact F_GETOWN/F_GETOWN_EX round trip.
                LINUX_F_SETOWN => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // fcntl(2): a positive arg is a process id, a negative arg is
                    // a process GROUP (-pgid).
                    let a = arg as i32;
                    let (owner_type, owner_pid) = if a < 0 {
                        (LINUX_F_OWNER_PGRP, a.wrapping_neg())
                    } else {
                        (LINUX_F_OWNER_PID, a)
                    };
                    open_file.description.common().set_captured_owner(
                        crate::kernel::objects::CapturedAsyncIoOwner::capture(
                            cx.kernel,
                            owner_type,
                            owner_pid,
                        ),
                    );
                    // Refresh the FASYNC registry if O_ASYNC is already armed on
                    // this fd (the owner can be set after O_ASYNC — LTP fcntl31).
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETOWN => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let owner = open_file.description.common().owner();
                    // A process-group owner reads back as a negative id.
                    let val = if owner.owner_type == LINUX_F_OWNER_PGRP {
                        owner.owner_pid.wrapping_neg()
                    } else {
                        owner.owner_pid
                    };
                    DispatchOutcome::returned_i32(val)
                }
                LINUX_F_SETOWN_EX => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let owner: LinuxFOwnerEx = cx.memory.read_struct(arg)?;
                    if owner.owner_type != LINUX_F_OWNER_TID
                        && owner.owner_type != LINUX_F_OWNER_PID
                        && owner.owner_type != LINUX_F_OWNER_PGRP
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    open_file.description.common().set_captured_owner(
                        crate::kernel::objects::CapturedAsyncIoOwner::capture(
                            cx.kernel,
                            owner.owner_type,
                            owner.owner_pid,
                        ),
                    );
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETOWN_EX => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let owner_info = open_file.description.common().owner();
                    let owner = LinuxFOwnerEx {
                        owner_type: owner_info.owner_type,
                        owner_pid: owner_info.owner_pid,
                    };
                    cx.memory.write_struct(arg, &owner)?;
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_SETSIG => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    // 0 = the default (SIGIO); otherwise a valid signal number.
                    let sig = arg as i32;
                    if !(0..=64).contains(&sig) {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    open_file.description.common().set_async_sig(sig);
                    // Refresh the registry: F_SETSIG can follow O_ASYNC + F_SETOWN
                    // (LTP fcntl31 sets the signal last), so the armed entry must
                    // pick up the new signal.
                    this.sync_fasync_registration(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_F_GETSIG => {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let sig = open_file.description.common().async_sig();
                    DispatchOutcome::returned_i32(sig)
                }
                _ => DispatchOutcome::errno(LINUX_EINVAL),
            })
        }

        fn flock(this, cx, fd: Fd, operation: u64) {
            let fd: Fd = fd;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };

            let lock_operation = operation & !LINUX_LOCK_NB;
            if !matches!(
                lock_operation,
                LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let file = {
                let Some(description) = open_file.description.read() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                Self::lease_file_identity(&description)
            };
            let Some(file) = file else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };

            let desc_ptr = Arc::as_ptr(&open_file.description) as usize;

            if lock_operation == LINUX_LOCK_UN {
                this.fs.classic_record_locks.unlock_flock(&file, desc_ptr);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let write = lock_operation == LINUX_LOCK_EX;
            let nonblocking = operation & LINUX_LOCK_NB != 0;

            match this
                .fs
                .classic_record_locks
                .try_flock(file.clone(), desc_ptr, write)
            {
                Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) if nonblocking => Ok(DispatchOutcome::errno(errno)),
                Err(_) => {
                    let tid = cx.tid();
                    match this.fs.classic_record_locks.wait_flock_interruptibly(
                        &file, desc_ptr, write, tid,
                    ) {
                        Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                        Err(errno) => Ok(DispatchOutcome::errno(errno)),
                    }
                }
            }
        }
    }
}
