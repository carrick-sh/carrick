use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use carrick_abi::{
    LINUX_EAGAIN, LINUX_EFAULT, LINUX_EINTR, LinuxErrno, SigBlockMask, SigSet, WaitSigMask,
};
use carrick_guest_mem::{
    CurrentMmMemory, Gpa, GuestMemory, GuestVa, MemoryError, SharedFutexLocation,
};
use carrick_hal::HostAliasBacking;
use serde::Serialize;
use thiserror::Error;

use super::sysv::SysvWaitState;
use super::wait_authority::WaitFds;
use super::{GuestPtr, HostAliasTransaction, HostSyscallResult};

#[derive(Debug)]
pub(crate) struct PinnedHostFd {
    fd: OwnedFd,
}

impl PinnedHostFd {
    pub(crate) fn new(fd: i32) -> Result<Self, LinuxErrno> {
        let duped = unsafe { libc::dup(fd) };
        if duped < 0 {
            let host = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EMFILE);
            return Err(crate::host_to_linux_errno(host));
        }
        // SAFETY: `duped` is a valid open descriptor from a successful `libc::dup`.
        let owned = unsafe { OwnedFd::from_raw_fd(duped) };
        Ok(Self { fd: owned })
    }

    pub(crate) fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

impl PartialEq for PinnedHostFd {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw_fd() == other.as_raw_fd()
    }
}

impl Eq for PinnedHostFd {}

/// Exact write target retained across a blocking-write continuation.
///
/// A host target owns a duplicated descriptor. An in-memory-pipe target owns
/// both the exact writer description's functional reference and the readiness
/// fd which represents that pipe's writable level. Neither variant ever
/// resolves a numeric guest fd after the syscall has parked.
#[derive(Clone)]
pub(crate) enum BlockingWriteTarget {
    Host(Arc<PinnedHostFd>),
    InMemoryPipe(Arc<crate::dispatch::fs::pipe::PipeWriteEndpointLease>),
}

impl PartialEq for BlockingWriteTarget {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Host(left), Self::Host(right)) => left == right,
            (Self::InMemoryPipe(left), Self::InMemoryPipe(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for BlockingWriteTarget {}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BlockingWrite {
    #[serde(skip_serializing)]
    pub(in crate::dispatch) target: BlockingWriteTarget,
    #[serde(skip_serializing)]
    pub(in crate::dispatch) bytes: Vec<u8>,
    /// Bytes already committed by earlier segments of the same writev call.
    /// `offset` is relative to `bytes`; Linux receives their sum.
    pub(in crate::dispatch) committed_prefix: usize,
    pub(in crate::dispatch) offset: usize,
    pub(in crate::dispatch) tid: crate::thread::ThreadId,
    pub(in crate::dispatch) sigpipe_on_epipe: bool,
}

impl BlockingWrite {
    pub(crate) fn from_vec(
        host_fd: i32,
        bytes: Vec<u8>,
        offset: usize,
        tid: crate::thread::ThreadId,
        sigpipe_on_epipe: bool,
    ) -> Result<Self, LinuxErrno> {
        Ok(Self {
            target: BlockingWriteTarget::Host(Arc::new(PinnedHostFd::new(host_fd)?)),
            bytes,
            offset,
            committed_prefix: 0,
            tid,
            sigpipe_on_epipe,
        })
    }

    pub(crate) fn poll_fd(&self) -> i32 {
        match &self.target {
            BlockingWriteTarget::Host(host_fd) => host_fd.as_raw_fd(),
            BlockingWriteTarget::InMemoryPipe(endpoint) => endpoint.readiness_fd().raw(),
        }
    }

    pub(crate) fn poll_events(&self) -> i16 {
        match &self.target {
            BlockingWriteTarget::Host(_) => libc::POLLOUT,
            BlockingWriteTarget::InMemoryPipe(_) => libc::POLLIN,
        }
    }

    pub(crate) fn offset(&self) -> usize {
        self.committed_prefix.saturating_add(self.offset)
    }

    pub(crate) fn tid(&self) -> crate::thread::ThreadId {
        self.tid
    }

    pub(crate) fn sigpipe_on_epipe(&self) -> bool {
        self.sigpipe_on_epipe
    }

    pub(crate) fn in_memory_pipe(
        endpoint: Arc<crate::dispatch::fs::pipe::PipeWriteEndpointLease>,
        bytes: Vec<u8>,
        offset: usize,
        tid: crate::thread::ThreadId,
        sigpipe_on_epipe: bool,
    ) -> Self {
        Self {
            target: BlockingWriteTarget::InMemoryPipe(endpoint),
            bytes,
            offset,
            committed_prefix: 0,
            tid,
            sigpipe_on_epipe,
        }
    }

    /// Extend an in-memory pipe continuation with staged writev bytes, then
    /// retain only the aggregate prefix that the pipe copy completed before a
    /// later guest-memory fault. `boundary` is the guest-visible byte count
    /// from the start of this writev call.
    pub(crate) fn with_in_memory_pipe_writev_boundary(
        mut self,
        tail: Vec<u8>,
        committed_prefix: usize,
        boundary: usize,
    ) -> Self {
        debug_assert!(matches!(self.target, BlockingWriteTarget::InMemoryPipe(_)));
        self.bytes.extend_from_slice(&tail);
        self.committed_prefix = committed_prefix;
        // `offset` has already been published to the pipe and cannot be
        // undone. The boundary can otherwise cut the parked current iovec as
        // well as later staged vectors.
        let retained = boundary
            .saturating_sub(committed_prefix)
            .max(self.offset)
            .min(self.bytes.len());
        self.bytes.truncate(retained);
        self
    }

    pub(crate) fn with_writev_tail(mut self, tail: Vec<u8>, committed_prefix: usize) -> Self {
        self.bytes.extend_from_slice(&tail);
        self.committed_prefix = committed_prefix;
        self
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn for_tests(
        host_fd: i32,
        bytes: Vec<u8>,
        offset: usize,
        tid: crate::thread::ThreadId,
        sigpipe_on_epipe: bool,
    ) -> Result<Self, LinuxErrno> {
        Self::from_vec(host_fd, bytes, offset, tid, sigpipe_on_epipe)
    }
}

impl std::fmt::Debug for BlockingWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingWrite")
            .field("poll_fd", &self.poll_fd())
            .field("bytes_len", &self.bytes.len())
            .field("offset", &self.offset())
            .field("tid", &self.tid)
            .field("sigpipe_on_epipe", &self.sigpipe_on_epipe)
            .finish()
    }
}

/// A parked `F_SETLKW`/`F_OFD_SETLKW`. Every record lock is arbitrated by
/// carrick's own logical table keyed on the guest's task/description identity;
/// the host `fcntl` transport was the retired lanes' answer, where one guest
/// process was one host process and the host kernel could own the arbitration.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BlockingRecordLock {
    #[serde(skip_serializing)]
    pub(in crate::dispatch) logical: super::fs::LogicalLockWait,
}

impl BlockingRecordLock {
    #[cfg(test)]
    pub(crate) fn logical(wait: super::fs::LogicalRecordLockWait) -> Self {
        Self::logical_lock(super::fs::LogicalLockWait::Record { wait, _lease: None })
    }

    pub(in crate::dispatch) fn logical_lock(wait: super::fs::LogicalLockWait) -> Self {
        Self { logical: wait }
    }
}

impl std::fmt::Debug for BlockingRecordLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingRecordLock")
            .field("logical", &self.logical)
            .finish()
    }
}

pub(crate) enum BlockingWriteStep {
    Done(DispatchOutcome),
    Wait,
}

pub(crate) fn drive_blocking_write(
    write: &mut BlockingWrite,
    host_signal: &dyn carrick_hal::HostSignalBridge,
) -> BlockingWriteStep {
    // Copy the target handle before mutating progress.  A parked continuation
    // owns this handle, so the clone keeps the same descriptor/endpoint
    // authority without borrowing `write.target` across the progress update.
    match write.target.clone() {
        BlockingWriteTarget::Host(host_fd) => {
            drive_host_blocking_write(write, &host_fd, host_signal)
        }
        BlockingWriteTarget::InMemoryPipe(endpoint) => {
            drive_in_memory_pipe_write(write, &endpoint, host_signal)
        }
    }
}

fn drive_host_blocking_write(
    write: &mut BlockingWrite,
    host_fd: &Arc<PinnedHostFd>,
    host_signal: &dyn carrick_hal::HostSignalBridge,
) -> BlockingWriteStep {
    loop {
        if write.offset >= write.bytes.len() {
            return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(
                write.committed_prefix + write.bytes.len(),
            ));
        }
        // BLOCKING-IO-OK: BlockingWrite pins a dup of a host fd that was
        // adopted non-blocking before the handoff; EAGAIN returns Wait below.
        let n = unsafe {
            libc::write(
                host_fd.as_raw_fd(),
                write.bytes[write.offset..].as_ptr() as *const _,
                write.bytes.len() - write.offset,
            )
        };
        crate::probes::host_pipe_io(host_fd.as_raw_fd(), 1, n as i64);
        if let Err(errno) = n.host_syscall_errno() {
            if errno == LINUX_EAGAIN || errno == LINUX_EINTR {
                if host_signal.has_unblocked_pending_for(write.tid.raw(), SigBlockMask::NONE) {
                    return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(
                        write.offset(),
                    ));
                }
                return BlockingWriteStep::Wait;
            }
            if write.offset() > 0 {
                return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(
                    write.offset(),
                ));
            }
            return BlockingWriteStep::Done(DispatchOutcome::Errno { errno });
        }
        if n == 0 {
            return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(write.offset()));
        }
        write.offset += n as usize;
        if write.offset >= write.bytes.len() {
            return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(
                write.committed_prefix + write.bytes.len(),
            ));
        }
        if host_signal.has_unblocked_pending_for(write.tid.raw(), SigBlockMask::NONE) {
            return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(write.offset()));
        }
    }
}

fn drive_in_memory_pipe_write(
    write: &mut BlockingWrite,
    endpoint: &Arc<crate::dispatch::fs::pipe::PipeWriteEndpointLease>,
    host_signal: &dyn carrick_hal::HostSignalBridge,
) -> BlockingWriteStep {
    if write.offset >= write.bytes.len() {
        return BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(
            write.committed_prefix + write.bytes.len(),
        ));
    }

    let pipe = endpoint.pipe();
    let mut state = pipe.state.lock();
    if state.readers == 0 {
        return if write.offset() == 0 {
            BlockingWriteStep::Done(DispatchOutcome::errno(carrick_abi::LINUX_EPIPE))
        } else {
            BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(write.offset()))
        };
    }
    let available = state.capacity.saturating_sub(state.buffer.len());
    if available == 0 {
        return BlockingWriteStep::Wait;
    }
    let chunk = (write.bytes.len() - write.offset).min(available);
    state
        .buffer
        .extend(&write.bytes[write.offset..write.offset + chunk]);
    write.offset += chunk;
    pipe.update_readiness_locked(&state);
    drop(state);
    pipe.changed.notify_all();
    endpoint.publish_progress(chunk);
    if write.offset >= write.bytes.len() {
        BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(
            write.committed_prefix + write.bytes.len(),
        ))
    } else if host_signal.has_unblocked_pending_for(write.tid.raw(), SigBlockMask::NONE) {
        BlockingWriteStep::Done(DispatchOutcome::returned_len_or_errno(write.offset()))
    } else {
        BlockingWriteStep::Wait
    }
}

pub(crate) fn drive_blocking_record_lock(
    lock: &BlockingRecordLock,
    host_signal: &dyn carrick_hal::HostSignalBridge,
) -> DispatchOutcome {
    match lock.logical.acquire(host_signal) {
        Ok(()) => DispatchOutcome::Returned { value: 0 },
        Err(errno) => DispatchOutcome::errno(errno),
    }
}

pub(crate) enum BlockingRecordLockStep {
    Done(DispatchOutcome),
    Wait,
}

/// Nonblocking record-lock progress for the shared continuation reactor.
/// Unlike `drive_blocking_record_lock`, this never issues F_SETLKW and never
/// parks the reactor thread behind a guest-owned lock.
pub(crate) fn try_drive_blocking_record_lock(lock: &BlockingRecordLock) -> BlockingRecordLockStep {
    match lock.logical.try_acquire() {
        Ok(()) => BlockingRecordLockStep::Done(DispatchOutcome::Returned { value: 0 }),
        Err(errno) if errno == LINUX_EAGAIN => BlockingRecordLockStep::Wait,
        Err(errno) => BlockingRecordLockStep::Done(DispatchOutcome::Errno { errno }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SharedFutexTarget {
    pub location: SharedFutexLocation,
    pub waiter_key: usize,
}

impl SharedFutexTarget {
    #[inline]
    pub const fn new(location: SharedFutexLocation, waiter_key: usize) -> Self {
        Self {
            location,
            waiter_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FdWaitCompletion {
    /// Plain fd wait completion semantics.
    Fd { on_timeout: i64 },
    /// Serviced by `poll(2)` instead of the runtime's per-thread kqueue.
    /// This is for epoll's backing kqueue fd:
    /// polling a kqueue fd observes pending epoll events without consuming
    /// them, so the runtime can re-dispatch `epoll_pwait` and let that call
    /// drain the epoll instance kqueue normally.
    Poll { on_timeout: i64 },
    /// Like [`DispatchOutcome::WaitOnFds`] but for `select`/`pselect6`, whose fd-set bitmaps are
    /// BOTH input and output (unlike `poll`'s separate `events`/`revents`).
    /// The handler therefore leaves the guest fd-sets UNMODIFIED across the
    /// wait, so:
    ///
    /// - a `Ready` re-dispatch re-reads the original input sets and reports
    ///   the now-ready fds (a fd that becomes ready *during* the block — the
    ///   primary use of select — is found correctly), and
    /// - an `Interrupted` (EINTR) return leaves the sets unmodified, exactly
    ///   as Linux specifies on signal interruption.
    ///
    /// Only `TimedOut` must present zeroed sets (select returns 0 with empty
    /// sets), which the runtime does by zeroing each `clear_on_timeout`
    /// `(guest_addr, byte_len)` range before completing the syscall with 0.
    /// `on_timeout` is implicitly 0 (a select timeout means "no fds ready").
    Select { clear_on_timeout: Vec<(u64, usize)> },
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOutcome {
    Returned {
        value: i64,
    },
    /// `sched_yield(2)` reached the threaded runtime. A bounded M:N backend
    /// must release its current vCPU lease before yielding so a runnable guest
    /// thread queued behind the budget can make progress; yielding only the
    /// host pthread retains the scarce lease and can deadlock oversubscribed
    /// thread groups. Unbounded backends reduce this to the historical host
    /// `yield_now` fast path.
    SchedulerYield,
    Errno {
        errno: LinuxErrno,
    },
    Exit {
        code: i32,
    },
    SignalDeath {
        signum: i32,
    },
    /// `clone(2)` with process-creation flags. The runtime must perform
    /// a real macOS fork against the trap engine, then write the child
    /// pid (parent) or 0 (child) into x0 to complete the syscall.
    ///
    /// `pidfd_out` is `Some(addr)` when `CLONE_PIDFD` was requested: the
    /// runtime allocates a pidfd for the new child and writes its (32-bit) fd
    /// to `addr` in the parent. Go's `os/exec` clones with `CLONE_PIDFD` and
    /// then waits on that fd.
    Fork {
        /// Complete clone flag set used to derive the authoritative kernel plan.
        flags: u64,
        pidfd_out: Option<u64>,
        /// `CLONE_PARENT`: the child is guest-parented to the caller's parent,
        /// even though Carrick must still create it as a host child of the
        /// caller. Runtime fork code records that guest parent in fork-coherent
        /// shared state.
        clone_parent: bool,
        /// `CLONE_PARENT_SETTID`: write the child's guest-visible pid/tid to
        /// this `pid_t *` before returning to the caller. Linux makes the store
        /// visible in the child as well for CLONE_VM; Carrick's process fork is
        /// CoW, so runtime fork code mirrors the write into both branches.
        parent_tid_addr: Option<u64>,
        /// `CLONE_CHILD_SETTID`: write the child's guest-visible pid/tid to
        /// this child-memory `pid_t *` before the child returns from clone.
        child_tid_addr: Option<u64>,
        /// Guest-requested exit signal (low byte of clone flags / clone3
        /// `exit_signal`). Delivered to the parent on child exit instead of a
        /// hardcoded SIGCHLD. `0` means "no exit signal" (e.g. `clone(0)`).
        exit_signal: u32,
        /// The clone's stack argument for an ORDINARY (non-vfork) fork-like
        /// clone: `0` (fork/clone(SIGCHLD, NULL) — the common case) keeps the
        /// parent's SP; a nonzero value runs the CHILD on that stack, exactly
        /// as the kernel does — glibc/musl's `__clone` stub then pops the
        /// child function off the NEW stack (LTP clone01 et al. crashed
        /// without this, the child resuming on the parent's frames).
        child_stack: u64,
        /// `CLONE_VFORK` (+`CLONE_VM`): the vfork-for-exec shape (Go `os/exec`,
        /// glibc `posix_spawn`). `Some(child_stack)` requests the vfork path — the
        /// runtime forks a child that SHARES the parent's guest RAM (not a CoW
        /// snapshot) and SUSPENDS the parent vCPU until the child `execve`s or
        /// `_exit`s. `child_stack` is the clone's stack argument: `0` (NULL, which
        /// Go uses) keeps the parent's SP, a nonzero value runs the child on that
        /// stack. `None` is an ordinary CoW fork.
        vfork: Option<u64>,
    },
    /// `execve(2)` succeeded so far in the dispatcher (path readable,
    /// argv/envp resolved). The runtime must:
    ///   1. Tear down the current guest address space.
    ///   2. Load the new ELF (handling the interpreter chain).
    ///   3. Rebuild the trap engine's mappings and vCPU state.
    ///
    /// Because `execve` does not return on success, the syscall has
    /// no retval to write into x0 — the runtime simply resumes the
    /// loop with the new entry point.
    Execve {
        path: String,
        // argv/env are opaque BYTE strings (Linux ABI), not UTF-8 — a guest may
        // legitimately pass non-UTF-8 args/env (e.g. CPython regrtest's
        // PYTHONREGRTEST_UNICODE_GUARD). The executable `path` stays a String
        // (resolved against the String/Path fs layer).
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    },
    /// Guest requested a change to the vCPU memory-ordering model via
    /// `prctl(PR_SET_MEM_MODEL, …)`. Apple Rosetta 2 issues this at startup to
    /// turn on hardware x86_64 TSO ordering. The dispatcher has no access to the
    /// vCPU, so the runtime loop performs the `ACTLR_EL1.EnTSO` write on the
    /// active vCPU thread and then completes the syscall with 0.
    SetMemoryModel {
        tso: bool,
    },
    /// Back a dynamic high-VA `mmap` (a guest VA at/above 1 TiB that can't be
    /// identity-mapped — HVF's IPA is 40 bits). Apple Rosetta reserves its
    /// translation working set at ~240 TiB. The runtime `hv_vm_map`s anonymous
    /// memory at `ipa`, builds a VA→IPA stage-1 path for `[va, va+len)`, and
    /// completes the `mmap` with `va`. The dispatcher has already reserved `ipa`
    /// from the low alias arena (`crate::memory::LINUX_ALIAS_IPA_BASE`).
    MapHostAlias {
        /// Opaque pending metadata commit. Every runtime consumer must claim it
        /// immediately before host mapping, then commit exactly once on full
        /// success or abort on any map/protection failure.
        transaction: HostAliasTransaction,
        va: GuestVa,
        ipa: Gpa,
        len: u64,
        /// Value the syscall returns on success. `mmap` answers with the
        /// mapped address; `mprotect`, which installs an alias lazily when it
        /// commits a reservation that never had backing, must answer 0 — a
        /// nonzero return there reads as failure to every libc wrapper.
        success_retval: i64,
        /// Bytes to copy into the freshly-mapped region at offset 0 (the file
        /// content for a snapshot mmap; empty for anonymous, which the host
        /// anon mapping already zeroes). Ignored for a file backing — a live
        /// file mapping is backed by the page cache directly.
        payload: Vec<u8>,
        /// What backs the host memory at `ipa`: an anonymous mapping (private
        /// or fork-coherent), or a file mapping — `MAP_SHARED` (guest writes
        /// reach the page cache, coherent with other openers) or `MAP_PRIVATE`
        /// (clean pages keep tracking later writes to the file, dirtied pages
        /// detach, exactly Linux's per-page COW). A shared file's `host_prot`
        /// MUST match the fd's access mode (a `PROT_WRITE` MAP_SHARED of a
        /// read-only fd is EACCES). The fd is a dup the backend owns and closes
        /// after mapping.
        backing: HostAliasBacking,
        /// Complete Linux `PROT_*` mask. Identity-native backends need all
        /// R/W/X bits to enforce guest accesses and translation eligibility;
        /// VMM backends may continue using `prot_none` for their leaf fast path.
        prot: u64,
        /// The guest asked for `PROT_NONE`: after installing the alias mapping
        /// the runtime must make the range guest-INACCESSIBLE (invalidate the
        /// fresh leaves), so the guest's own access faults (SIGSEGV/ACCERR)
        /// instead of reaching the host backing — which for a PROT_NONE
        /// `MAP_SHARED` file is itself mapped `PROT_NONE`, and a guest touch
        /// through a present leaf crashes the vCPU (KVM_RUN EFAULT / stage-2
        /// abort: LTP mmap05's TBROK).
        prot_none: bool,
    },
    /// Guest invoked `rt_sigreturn(2)` (syscall 139). The runtime must
    /// pop the Carrick sigframe at SP_EL0, restore the saved register
    /// state, and resume — without advancing PC the way a normal SVC
    /// completion would. There is no retval to write into x0; the
    /// restored x0 IS the return value.
    SigReturn,
    /// Thread-creating `clone(2)`/`clone3(2)` (CLONE_VM|CLONE_THREAD|...).
    /// The runtime spawns a new host thread + vCPU sharing this process's VM.
    CloneThread {
        stack: u64,       // child SP (clone arg)
        tls: Option<u64>, // CLONE_SETTLS value -> TPIDR_EL0
        flags: u64,
        parent_tid_addr: u64,      // CLONE_PARENT_SETTID target (0 = none)
        child_tid_addr: u64,       // CLONE_CHILD_SETTID target (0 = none)
        clear_child_tid_addr: u64, // CLONE_CHILD_CLEARTID target (0 = none)
    },
    /// A single thread exited via `exit(2)` (NOT exit_group): the runtime
    /// performs the CLONE_CHILD_CLEARTID futex wake and ends just this host
    /// thread. If it was the last live thread the process exits.
    ThreadExit {
        code: i32,
    },
    /// Guest `tgkill`/`tkill` targeting a *sibling* thread (not self). The
    /// handler can't reach the target's vCPU, so the runtime publishes the
    /// signal for `tid` and forces that vCPU out of the guest (vcpu_kick) so it
    /// delivers promptly. Completes the calling syscall with 0, or -ESRCH if
    /// the target raced to exit. Only emitted on the multi-threaded path.
    SignalThread {
        tid: crate::thread::ThreadId,
        signum: i32,
        #[serde(skip)]
        kernel_target: Option<crate::kernel::ThreadKey>,
    },
    /// `FUTEX_WAIT` whose value-check passed under the dispatcher lock: the
    /// guest word equals the expected value, so this thread must block.
    /// The handler CANNOT block while holding the dispatcher lock (a sibling's
    /// `FUTEX_WAKE` would deadlock), so it returns this outcome and the
    /// runtime drops the lock, parks on the prepared futex token, then completes the
    /// syscall with 0 (woken) or -ETIMEDOUT (timed out).
    FutexWait {
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
    },
    FutexWaitv {
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
        index: i64,
    },
    /// A `FUTEX_WAIT` on a genuine `MAP_SHARED` file mapping — an inter-PROCESS
    /// rendezvous (LTP `tst_checkpoint`). The in-process parking-lot table can't
    /// reach a waker in another carrick process, so the runtime blocks on the
    /// host `__ulock` keyed by the SHARED physical page (`host_addr` is the host
    /// VA of the futex word). Like `FutexWait` it must not block under the
    /// dispatcher lock; the runtime waits interruptibly and completes the
    /// syscall. `value` is the expected futex word (the kernel re-compares).
    SharedFutexWait {
        target: SharedFutexTarget,
        generation: crate::thread::FutexWait,
        value: u32,
        timeout: Option<Duration>,
    },
    SharedFutexWaitv {
        target: SharedFutexTarget,
        generation: crate::thread::FutexWait,
        value: u32,
        timeout: Option<Duration>,
        index: i64,
    },
    /// A `FUTEX_WAKE` on a genuine `MAP_SHARED` mapping — the cross-PROCESS wake
    /// counterpart of [`DispatchOutcome::SharedFutexWait`]. The wake must reach a
    /// waiter parked in ANOTHER carrick process on the same physical page, so it
    /// is routed through the `PlatformFutex::shared_wake` seam (HVF → `__ulock`
    /// one-at-a-time with `sched_yield`; KVM → host `SYS_futex(FUTEX_WAKE)`).
    /// The handler returns this outcome (instead of calling the backend wake
    /// inline) so the loop reaches the same `PlatformFutex` the `SharedFutexWait`
    /// side uses, keeping the wait/wake pair on ONE seam. `count` is the guest's
    /// requested wake count (`FUTEX_WAKE`'s `val`); the loop completes the syscall
    /// with the number actually woken.
    SharedFutexWake {
        target: SharedFutexTarget,
        count: u32,
    },
    SharedFutexRequeue {
        from: SharedFutexTarget,
        to: SharedFutexTarget,
        wake: u32,
        requeue: u32,
    },
    /// Wait until an internal fork-shared word changes, then re-dispatch the
    /// original syscall. This is for runtime-owned kernel objects such as SysV
    /// message queues: the wait condition is not the syscall result, it only says
    /// the object state might have changed. The loop must release dispatcher and
    /// vCPU resources while parked, then retry the handler under fresh state.
    WaitOnSharedWord {
        location: SharedFutexLocation,
        waiter_key: usize,
        generation: crate::thread::FutexWait,
        value: u32,
        /// Owned SysV message-queue wait authority. This keeps the exact
        /// wait-word mmap/fd and blocked queue id alive across executor
        /// suspension; `None` is reserved for non-SysV runtime-owned words.
        #[serde(skip_serializing)]
        sysv: Option<SysvWaitState>,
    },
    /// A blocking-mode I/O syscall (ppoll/pselect/poll/select with no fd ready,
    /// or — later — recvfrom/accept/read that would block) needs to wait for
    /// host-fd readiness. Like `FutexWait`, the handler MUST NOT block while
    /// holding the dispatcher lock — that starves every sibling thread (CPython's
    /// GIL handoff, a server's worker threads, see the "dispatcher lock"). It
    /// returns this outcome; the runtime drops the lock, `libc::poll`s the host
    /// fds (signal-interruptible) up to `timeout`, then either completes the
    /// syscall (timeout → 0, signal → EINTR) or re-dispatches it (a fd became
    /// ready → the handler now finds it and returns the revents). The handler
    /// has already written zeroed revents into guest memory, so a timeout
    /// completion needs no further writes.
    WaitOnFds {
        /// (host_fd, poll events) pairs to wait on.
        fds: WaitFds,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// The wait's signal-masking policy. `Replace(set)` carries a POSIX
        /// sigmask that REPLACES the thread's persistent mask for the wait
        /// (`ppoll`/`pselect6`/`epoll_pwait`): a signal blocked by the set does
        /// NOT interrupt the wait (it stays pending and is delivered after the
        /// syscall), and a signal the set UNBLOCKS must interrupt even if
        /// persistently blocked — the interrupt predicate uses the set ALONE.
        /// `Additive(set)` (the default for plain `read`/`recv`/`connect`,
        /// usually with an empty set) means the effective wait mask is the
        /// thread's persistent mask plus the set. (probe `ppollunblock` vs
        /// `maskfork`.)
        sig_mask: WaitSigMask,
        /// Completion behavior distinguishing fd, poll, and select wait semantics.
        completion: FdWaitCompletion,
    },
    /// A blocking `write(2)` to a host FIFO made partial progress and then hit
    /// host EAGAIN. Re-dispatching the original syscall would duplicate the
    /// written prefix, while parking inside the dispatcher would starve sibling
    /// threads that may close the read end or deliver the interrupting signal.
    /// The runtime owns this staged continuation, waits for POLLOUT with the
    /// dispatcher lock released, and completes with the Linux-visible result.
    BlockingWrite(BlockingWrite),
    /// A timerfd read waiting on a Carrick-owned timer.  Unlike a generic fd
    /// wait, this owns the exact description and must complete that operation
    /// even if its numeric fd was subsequently reused.
    BlockingTimerFdRead(#[serde(skip)] crate::dispatch::format_time::BlockingTimerFdRead),
    /// A parsed SysV semaphore operation parked outside the dispatcher.  It
    /// retains the exact semaphore-set generation and operation array, so an
    /// `IPC_RMID`/id-reuse race cannot retarget completion.
    BlockingSemop(#[serde(skip)] crate::dispatch::sysv::BlockingSemop),
    /// A POSIX message-queue send or receive parked outside the dispatcher.
    /// It retains the exact queue and captured operation across fd close/reuse.
    BlockingMqueue(#[serde(skip)] crate::dispatch::mqueue::BlockingMqueue),
    /// Retained poll/select operation.  Its completion samples the admission
    /// snapshot and either writes final output or re-parks itself.
    BlockingFdWait {
        #[serde(skip)]
        wait: crate::dispatch::fd_wait::BlockingFdWait,
        sig_mask: WaitSigMask,
    },
    /// A pending record-lock or flock operation. The dispatcher retains its
    /// parsed request and exact ownership; the continuation reactor attempts
    /// acquisition without occupying a guest executor while a conflict remains.
    BlockingRecordLock(BlockingRecordLock),
    /// An in-process HvPatch child is still running. There is no Darwin child
    /// fd/kqueue event to wait on, so the threaded loop performs a short,
    /// signal/fork-interruptible park and re-dispatches the original wait.
    WaitOnHvpatchChild {
        /// Exact guest PID for `wait4(pid)` / `waitid(P_PID, pid)`, or `None`
        /// for an any-child selector. This is guest-domain process identity;
        /// no Darwin child process exists for HvPatch.
        target: Option<i32>,
        sig_mask: WaitSigMask,
        /// The parent's wake generation as of the scan that found nothing to
        /// reap. The continuation must enroll against THIS, not against a
        /// generation re-read when it is captured: a child that exits in
        /// between publishes its edge before the capture, and a capture-time
        /// reading then subscribes past it and parks forever.
        precheck: crate::kernel::ChildWaitPrecheck,
    },
    /// A synchronous signal wait found no matching signal already pending and
    /// must wait until one of `wait_set` arrives, or until `timeout` elapses.
    /// `rt_sigtimedwait` uses its caller-supplied timeout; `rt_sigsuspend` uses
    /// `None` after installing its temporary mask and saved-mask restoration.
    /// The runtime
    /// parks without holding dispatcher locks, wakes for matching signals
    /// (re-dispatching the same syscall so the dispatcher can dequeue the
    /// signal and write `siginfo_t` through the original guest pointer) — OR
    /// for an unblocked signal OUTSIDE `wait_set`, which must interrupt the
    /// wait with EINTR after its handler is delivered (sigtimedwait is never
    /// restarted, even under SA_RESTART — signal(7)).
    WaitOnSignals {
        wait_set: SigSet,
        /// Signals that must NOT wake the park
        /// ([`carrick_abi::SigBlockMask::for_signal_wait`], precomputed at
        /// dispatch). The distinct TYPE exists because passing `!wait_set`
        /// here was the empty-set hang: `rt_sigtimedwait(set=∅, NULL)`
        /// blocked every signal, so the unblocked caught signal that must
        /// EINTR the wait (LTP sigtimedwait01 et al.) could never wake the
        /// waiter.
        block_mask: SigBlockMask,
        timeout: Option<Duration>,
    },
    /// A relative sleep (`nanosleep`/`clock_nanosleep`). The run loop performs
    /// the timed wait via the per-thread waiter — NOT a blocking host nanosleep
    /// inside the dispatcher — so the sleep is interruptible by a guest signal
    /// (EINTR) AND, critically, can PARK for a fork-quiesce: a sibling stuck in
    /// a synchronous host nanosleep never reaches the run-loop top, so a
    /// multithreaded fork would otherwise deadlock waiting for it to quiesce.
    /// The run loop preserves the deadline across re-dispatch (quiesce-park),
    /// so the sleep is not restarted. `duration` is the (relative) remaining
    /// time; an ABSTIME clock_nanosleep is pre-converted by the handler.
    WaitOnSleep {
        duration: Duration,
        remaining: Option<GuestPtr>,
    },
}

impl DispatchOutcome {
    /// Construct an errno outcome. The guest receives `-errno`.
    #[inline]
    pub fn errno(errno: LinuxErrno) -> Self {
        DispatchOutcome::Errno { errno }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearMemory {
    pub(in crate::dispatch) base: u64,
    pub(in crate::dispatch) bytes: Vec<u8>,
}

impl LinearMemory {
    pub fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self { base, bytes }
    }
}

impl GuestMemory for LinearMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(self.bytes[offset..end].to_vec())
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        let offset = usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })?;
        let end = offset
            .checked_add(bytes.len())
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}

impl CurrentMmMemory for LinearMemory {}

#[derive(Debug, Error)]
#[allow(private_interfaces)]
pub enum DispatchError {
    #[error("guest memory read length does not fit this host: {0}")]
    LengthTooLarge(u64),
    #[error("syscall interceptor panicked in container {container_id:?}")]
    InterceptorPanicked {
        container_id: crate::kernel::ContainerId,
    },
    /// A guest-visible errno. Unlike [`DispatchError::LengthTooLarge`] (which is
    /// a fatal, unrepresentable condition that aborts the run), this is lowered
    /// to a [`DispatchOutcome::Errno`] at the dispatch boundary
    /// ([`lower_handler_result`]). It lets a handler `?`-propagate an errno —
    /// `let x = helper()?;` instead of `match helper() { Err(e) => return
    /// Ok(e.into()), Ok(v) => v }` — collapsing the pervasive errno-forwarding
    /// boilerplate. The guest observes exactly the same `-errno` either way.
    #[error("guest-visible errno: {}", .0.get())]
    Errno(LinuxErrno),
    #[error("fatal file authority error: {0:?}")]
    FileAuthorityFatal(crate::file_authority::AuthorityFatal),
    #[error("MM executor admission failed: {0}")]
    MmExecutorAdmission(crate::kernel::GuestExecutorCensusError),
    #[error("MM mutation requires a page-table pause while a peer executor is active")]
    MmMutationPeerExecutor,
    #[error("caller-MM executor release requires an active executor participation")]
    MmExecutorParticipationUnavailable,
    #[error("caller-MM executor release requires an exact running execution lease")]
    MmExecutorExecutionLeaseUnavailable,
    #[error("caller-MM executor is bound to a different dispatch MM")]
    MmExecutorBindingDrift,
    #[error("caller-MM executor authority {executor:?} does not match kernel MM {kernel:?}")]
    MmExecutorKernelMmMismatch {
        executor: crate::kernel::MmId,
        kernel: crate::kernel::MmId,
    },
    #[error("caller-MM executor thread identity does not match the syscall context")]
    MmExecutorThreadIdentityMismatch,
    #[error("caller-MM execution lease is not the exact running lease: {0}")]
    MmExecutorExecutionLease(crate::kernel::objects::ThreadExecutionError),
    #[error("caller-MM execution lease names MM {lease:?}, expected {executor:?}")]
    MmExecutorExecutionMmMismatch {
        executor: crate::kernel::MmId,
        lease: crate::kernel::MmId,
    },
}

impl From<crate::file_authority::AuthorityFatal> for DispatchError {
    fn from(fatal: crate::file_authority::AuthorityFatal) -> Self {
        DispatchError::FileAuthorityFatal(fatal)
    }
}

impl From<LinuxErrno> for DispatchError {
    /// A typed Linux errno propagated via `?` becomes [`DispatchError::Errno`],
    /// lowered back to a guest errno outcome at the dispatch boundary.
    fn from(errno: LinuxErrno) -> Self {
        DispatchError::Errno(errno)
    }
}

impl From<MemoryError> for DispatchError {
    /// A guest-memory access fault is the guest handing us a bad pointer →
    /// `EFAULT`. Lets handlers `?`-propagate `memory.read_bytes(..)` /
    /// `write_bytes(..)` directly instead of the `match { Err(_) => return
    /// Ok(DispatchOutcome::errno(LINUX_EFAULT)) }` boilerplate (in handlers
    /// returning `Result<_, DispatchError>`; helpers returning
    /// `Result<_, LinuxErrno>` keep `.map_err(|_| LINUX_EFAULT)?`).
    fn from(_: MemoryError) -> Self {
        DispatchError::Errno(LINUX_EFAULT)
    }
}

/// Lower a syscall handler's result for the run loop. A
/// [`DispatchError::Errno`] is a guest-visible errno, so it becomes a normal
/// [`DispatchOutcome::Errno`]; every other `DispatchError` variant is a fatal
/// condition that stays `Err` and aborts the guest run. This is what lets
/// handlers `?`-propagate an errno while `LengthTooLarge` still aborts.
pub(crate) fn lower_handler_result(
    result: Result<DispatchOutcome, DispatchError>,
) -> Result<DispatchOutcome, DispatchError> {
    match result {
        Err(DispatchError::Errno(errno)) => Ok(DispatchOutcome::Errno { errno }),
        other => other,
    }
}
