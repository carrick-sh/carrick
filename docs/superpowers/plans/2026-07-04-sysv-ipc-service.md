# SysV IPC Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Carrick's file-rewrite SysV message-queue hot path with a runtime-owned, fork-coherent SysV IPC service that passes the focused SysV LTP cluster without shaping unrelated procfs thread capacity.

**Architecture:** Dispatch remains the Linux syscall wire boundary, but message queue identity, metadata, storage, procfs snapshots, and blocking semantics move behind `SysvIpcService`. The first behavior-preserving task creates the facade around the current implementation; later tasks replace the queue-file storage with one run-scoped shared service mapping and explicit process-shared futex wait/wake.

**Tech Stack:** Rust 2024, Carrick `just` recipes, `bitflags`, `zerocopy`, `libc`, mmap-backed shared state, Carrick shared futex abstraction, `carrick trace`, Docker oracle, LTP 20260529.

## Global Constraints

- Use `just` entrypoints; any guest run or conformance gate must use a signed binary from `just build`, `just run`, or `just conformance`.
- Never run Carrick and the Docker oracle concurrently.
- Do not read Linux kernel source; derive SysV behavior from man pages, ABI docs, and Docker oracle traces.
- Do not add known-gaps, baseline edits, shell wrappers, or suite-specific harness overrides.
- Do not tune `/proc/sys/kernel/threads-max` to pass `msgstress01`.
- Typed domain values are required at service boundaries; raw `u32`, `u64`, `i32`, and `i64` values may enter and leave only at syscall wire, procfs text, libc, atomic, and shared-memory layout boundaries.
- New flag domains must use `bitflags!`; new command domains should use ordinal enums where it improves dispatch clarity.
- Keep SysV IPC semantics separate from M:N scheduling and vCPU admission; blocking waits may release vCPU resources, but IPC correctness must not depend on that.
- Commit logically after each independently passing task, with a Conventional Commit subject, explanatory body, verification line, and `Co-Authored-By: Codex <codex@openai.com>`.

---

## File Structure

- Modify: `crates/carrick-runtime/src/vfs/proc.rs`
  - Remove the tactical Carrick-specific `threads-max` clamp and restore `/proc/sys/kernel/threads-max` to a host-derived or conservative Linux-facing value that is not shaped for SysV LTP.
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs`
  - Keep SysV shm and semaphore code in place.
  - Add typed message service facade types in the existing module first to avoid broad module churn in a dirty tree.
  - Move current message-queue functions behind `SysvIpcService`.
  - Replace queue-file hot path with a run-scoped shared service mapping.
  - Route `/proc/sysvipc/msg`, `msgctl`, `msgget`, `msgsnd`, and `msgrcv` through the service.
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
  - Replace direct `Mutex<sysv::SysvShmState>` message access with `SysvShmState` holding or exposing `SysvIpcService`.
- Modify: `crates/carrick-runtime/src/runtime.rs`
  - Keep existing process-exit cleanup calls, but ensure `IPC_RMID` and run cleanup notify the service.
- Modify: `conformance-probes/src/bin/sysvmsg.rs`
  - Update stale comments that still claim Carrick forwards to host Darwin SysV queues.
  - Extend deterministic probe coverage for nonblocking empty/full behavior, `IPC_RMID` wake, and type-selection edge cases.
- Create: `conformance-probes/src/bin/sysvmsgwake.rs`
  - Focused forked sender/receiver and `IPC_RMID` wake probe that fails red before explicit wait/wake is implemented.
- Modify: `scripts/conformance/suites.toml`
  - Add the new probe binary to `conformance-probes` only if the probe harness requires explicit suite registration.
- Keep: `scripts/dtrace/msgstress-sysv.d`
  - Diagnostic script for queue progress and `EAGAIN` loops.
- Keep: `scripts/dtrace/msgstress-fork-sysv.d`
  - Diagnostic script for fork/admission shape.

---

### Task 1: Remove Procfs Thread Shaping

**Files:**
- Modify: `crates/carrick-runtime/src/vfs/proc.rs`

**Interfaces:**
- Consumes: Existing `Sysctl::Dynamic(fn() -> Vec<u8>)` and `SYSCTL_TABLE`.
- Produces: `/proc/sys/kernel/threads-max` no longer clamps to `70` for SysV workload shaping.

- [ ] **Step 1: Confirm current shaped value is present**

Run:

```bash
rg -n "ThreadCapacity|CARRICK_PROCESS_FANOUT_THREADS_MAX|sysctl_threads_max|Host-powered, Carrick-clamped" crates/carrick-runtime/src/vfs/proc.rs
```

Expected: matches include `CARRICK_PROCESS_FANOUT_THREADS_MAX` and the comment that says `Carrick-clamped process fanout`.

- [ ] **Step 2: Replace the shaping helper with a non-SysV-specific helper**

In `crates/carrick-runtime/src/vfs/proc.rs`, replace the `ThreadCapacity` block with:

```rust
#[derive(Clone, Copy)]
struct KernelThreadLimit(u64);

impl KernelThreadLimit {
    const fn new(value: u64) -> Self {
        Self(value)
    }

    const fn raw(self) -> u64 {
        self.0
    }
}

const DEFAULT_THREADS_MAX: KernelThreadLimit = KernelThreadLimit::new(63_087);

fn sysctl_threads_max() -> Vec<u8> {
    let limit = host_threads_max().unwrap_or(DEFAULT_THREADS_MAX);
    format!("{}\n", limit.raw()).into_bytes()
}

fn host_threads_max() -> Option<KernelThreadLimit> {
    host_rlimit_nproc().or_else(host_kernel_threads_max)
}

fn host_rlimit_nproc() -> Option<KernelThreadLimit> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `getrlimit` initializes the passed `rlimit` on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, limit.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: success above initialized `limit`.
    let limit = unsafe { limit.assume_init() };
    if limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur == 0 {
        None
    } else {
        Some(KernelThreadLimit::new(limit.rlim_cur))
    }
}

#[cfg(target_os = "linux")]
fn host_kernel_threads_max() -> Option<KernelThreadLimit> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/threads-max").ok()?;
    raw.trim().parse::<u64>().ok().map(KernelThreadLimit::new)
}

#[cfg(target_os = "macos")]
fn host_kernel_threads_max() -> Option<KernelThreadLimit> {
    host_sysctl_u64("kern.maxprocperuid")
        .or_else(|| host_sysctl_u64("kern.maxproc"))
        .map(KernelThreadLimit::new)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_kernel_threads_max() -> Option<KernelThreadLimit> {
    None
}
```

Update the `SYSCTL_TABLE` comment above `threads-max` to:

```rust
    // Host-powered process/thread ceiling. This is intentionally not used to
    // tune SysV IPC workloads; queue throughput belongs to the SysV service.
```

- [ ] **Step 3: Run focused checks**

Run:

```bash
just fmt-check
just check -p carrick-runtime
```

Expected: both pass.

- [ ] **Step 4: Commit**

Run:

```bash
git add crates/carrick-runtime/src/vfs/proc.rs
git diff --cached -- crates/carrick-runtime/src/vfs/proc.rs
git commit -m "fix(runtime): stop shaping threads-max for sysv ipc"
```

Commit body:

```text
The SysV message stress failure was a queue-service throughput and wakeup
problem, not a reason to advertise a smaller unrelated process/thread ceiling.
Clamping threads-max made LTP choose less work and hid the architecture issue.

Keep the value host-powered, with a conservative fallback, and make the comment
explicit that SysV IPC capacity belongs to the SysV service instead of procfs
workload shaping.

Verified:
- just fmt-check
- just check -p carrick-runtime

Co-Authored-By: Codex <codex@openai.com>
```

---

### Task 2: Add SysvIpcService Facade Without Behavior Change

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `conformance-probes/src/bin/sysvmsg.rs`

**Interfaces:**
- Consumes: Existing `SysvShmState`, `MsgQueueFile`, `MsgQueueLock`, `msgget_open`, `msg_queue_try_send`, `msg_queue_receive`, and `sysv_msgctl`.
- Produces:
  - `pub(super) struct SysvIpcService`
  - `impl SysvIpcService { fn new() -> Self; fn after_fork_child(&mut self); fn msg_table(&self) -> String; fn cleanup_process_exit(&mut self); fn msgget(&mut self, creds: &super::creds::CredState, key: MsgKey, flags: u64) -> Result<MsgQueueId, LinuxErrno>; fn msgsnd(&mut self, id: MsgQueueId, creds: &super::creds::CredState, msg_type: MsgType, payload: &[u8]) -> Result<bool, LinuxErrno>; fn msgrcv<M: GuestMemory>(&mut self, cx: &mut SyscallCtx<M>, id: MsgQueueId, creds: &super::creds::CredState, msgp: u64, msgsz: usize, wanted: MsgType, flags: MsgOpFlags) -> Result<Option<usize>, LinuxErrno>; fn msgctl<M: GuestMemory>(&mut self, cx: &mut SyscallCtx<M>, msqid: u64, cmd: u64, buf: u64, creds: &super::creds::CredState) -> Result<DispatchOutcome, LinuxErrno>; }`

- [ ] **Step 1: Update stale probe comments**

In `conformance-probes/src/bin/sysvmsg.rs`, replace the top comment with:

```rust
//! SysV message queues: msgget / msgsnd / msgrcv / msgctl(IPC_STAT/IPC_RMID).
//! Carrick implements these as Linux SysV IPC objects owned by the runtime.
//! The probe checks cross-process behavior because guest forks are real host
//! processes and queue state must be fork-coherent inside one Carrick run.
//!
//! Invariants (deterministic):
```

- [ ] **Step 2: Add typed key and byte wrappers**

Near `MsgQueueId` in `crates/carrick-runtime/src/dispatch/sysv.rs`, add:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MsgKey(i32);

impl MsgKey {
    const PRIVATE: Self = Self(LINUX_IPC_PRIVATE);

    fn from_syscall_arg(value: u64) -> Result<Self, LinuxErrno> {
        let raw = i32::try_from(value).map_err(|_| LINUX_EINVAL)?;
        Ok(Self(raw))
    }

    fn raw(self) -> i32 {
        self.0
    }

    fn is_private(self) -> bool {
        self == Self::PRIVATE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct MsgBytes(u64);

impl MsgBytes {
    fn from_payload_len(value: usize) -> Result<Self, LinuxErrno> {
        u64::try_from(value)
            .map(Self)
            .map_err(|_| LINUX_EINVAL)
    }

    fn raw(self) -> u64 {
        self.0
    }
}
```

- [ ] **Step 3: Introduce the facade type**

In `crates/carrick-runtime/src/dispatch/sysv.rs`, change `SysvShmState` to hold the service:

```rust
pub(super) struct SysvShmState {
    next_private: u64,
    segments: HashMap<i32, ShmSegment>,
    attachments: HashMap<u64, ShmSegment>,
    semaphores: HashMap<GuestSemId, HostSemId>,
    sem_nsems: HashMap<GuestSemId, usize>,
    next_semid: i32,
    message_queues: HashSet<MsgQueueId>,
    msg_service: SysvIpcService,
}
```

Initialize it in `SysvShmState::new()` with:

```rust
            msg_service: SysvIpcService::new(),
```

Add this facade below `SysvShmState::new()`:

```rust
pub(super) struct SysvIpcService;

impl SysvIpcService {
    fn new() -> Self {
        Self
    }

    fn after_fork_child(&mut self) {
        MSG_QUEUE_FD_CACHE.with(|cache| cache.borrow_mut().refresh_for_current_process());
    }

    fn cleanup_process_exit(&mut self) {
        cleanup_msg_queue_files_for_scope();
    }

    fn msg_table(&self) -> String {
        sysvipc_msg_table_from_files()
    }
}
```

Rename the body of `SyscallDispatcher::sysvipc_msg_table` to a free function:

```rust
fn sysvipc_msg_table_from_files() -> String {
    let mut out = String::from("       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n");
    for id in sorted_msg_queue_ids() {
        let Ok(path) = lookup_msg_queue_path(id) else {
            continue;
        };
        let Ok(lock) = MsgQueueLock::acquire(&path) else {
            continue;
        };
        let Ok(queue) = lock.read_queue() else {
            continue;
        };
        out.push_str(&format!(
            "{:10} {:10} {:5o} {:11} {:10} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
            queue.key,
            queue.id.raw(),
            queue.mode.perms(),
            queue.cbytes,
            queue.qnum,
            queue.lspid,
            queue.lrpid,
            queue.uid,
            queue.gid,
            queue.cuid,
            queue.cgid,
            queue.stime,
            queue.rtime,
            queue.ctime
        ));
    }
    out
}
```

- [ ] **Step 4: Route dispatcher table through the facade**

Change `SyscallDispatcher::sysv_after_fork_child()` to call:

```rust
        state.msg_service.after_fork_child();
```

Change `SyscallDispatcher::sysvipc_msg_table()` to:

```rust
    pub(crate) fn sysvipc_msg_table(&self) -> String {
        let state = self.sysv.lock();
        state.msg_service.msg_table()
    }
```

Keep `cleanup_sysv_ipc_on_process_exit()` removing message files through the facade:

```rust
            state.msg_service.cleanup_process_exit();
```

- [ ] **Step 5: Run behavior-preserving gates**

Run:

```bash
just fmt-check
just check -p carrick-runtime
just conformance-probes
```

Expected: all pass; SysV probe output still reports `msgget_ok=true`, `send_recv_roundtrip=true`, `xprocess_send_recv=true`, and `ipc_rmid_ok=true`.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/carrick-runtime/src/dispatch/sysv.rs crates/carrick-runtime/src/dispatch/mod.rs conformance-probes/src/bin/sysvmsg.rs
git diff --cached -- crates/carrick-runtime/src/dispatch/sysv.rs crates/carrick-runtime/src/dispatch/mod.rs conformance-probes/src/bin/sysvmsg.rs
git commit -m "refactor(runtime): route sysv messages through service facade"
```

Commit body:

```text
Message queue state was still owned as file helpers directly under dispatch,
which made it too easy for syscall handlers, procfs, and cleanup to grow
separate behavior. The approved SysV IPC design needs one runtime service
boundary before the storage and wakeup internals can change.

Add `SysvIpcService` as the narrow facade around the current implementation and
route procfs snapshots, fork refresh, and process-exit cleanup through it
without changing queue behavior. Also fix the probe comment that still claimed
Darwin SysV queues were the backing store.

Verified:
- just fmt-check
- just check -p carrick-runtime
- just conformance-probes

Co-Authored-By: Codex <codex@openai.com>
```

---

### Task 3: Add Red-First SysV Wake and Fanout Probe

**Files:**
- Create: `conformance-probes/src/bin/sysvmsgwake.rs`
- Modify: `scripts/conformance/suites.toml` if probe registration is explicit.

**Interfaces:**
- Consumes: Linux syscalls `msgget`, `msgsnd`, `msgrcv`, `msgctl`, `fork`, `waitpid`, `kill`, `alarm`.
- Produces: A deterministic probe binary with report keys:
  - `nowait_empty_enomsg`
  - `nowait_full_eagain`
  - `fork_reader_wakes_sender`
  - `rmid_wakes_receiver`

- [ ] **Step 1: Create the probe**

Create `conformance-probes/src/bin/sysvmsgwake.rs` with:

```rust
use conformance_probes::{errno, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
const IPC_NOWAIT: i32 = 0o4000;
const ENOMSG: i32 = 42;
const EAGAIN: i32 = 11;
const EIDRM: i32 = 43;
const LIN_MSG_QBYTES_OFF: usize = 88;

#[repr(C)]
struct Msgbuf {
    mtype: i64,
    mtext: [u8; 64],
}

unsafe fn msgget(key: i32, flg: i32) -> i64 {
    libc::syscall(libc::SYS_msgget, key, flg)
}

unsafe fn msgsnd(id: i32, msgp: *const Msgbuf, sz: usize, flg: i32) -> i64 {
    libc::syscall(libc::SYS_msgsnd, id, msgp, sz, flg)
}

unsafe fn msgrcv(id: i32, msgp: *mut Msgbuf, sz: usize, typ: i64, flg: i32) -> i64 {
    libc::syscall(libc::SYS_msgrcv, id, msgp, sz, typ, flg)
}

unsafe fn msgctl(id: i32, cmd: i32, buf: *mut u8) -> i64 {
    libc::syscall(libc::SYS_msgctl, id, cmd, buf)
}

unsafe fn set_qbytes(id: i32, qbytes: u64) -> bool {
    let mut ds = [0u8; 120];
    if msgctl(id, IPC_STAT, ds.as_mut_ptr()) != 0 {
        return false;
    }
    ds[LIN_MSG_QBYTES_OFF..LIN_MSG_QBYTES_OFF + 8].copy_from_slice(&qbytes.to_le_bytes());
    msgctl(id, IPC_SET, ds.as_mut_ptr()) == 0
}

fn child_exited_zero(status: i32) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn main() {
    unsafe {
        libc::alarm(20);
        let id = msgget(IPC_PRIVATE, IPC_CREAT | 0o600);
        if id < 0 {
            report!(
                nowait_empty_enomsg = false,
                nowait_full_eagain = false,
                fork_reader_wakes_sender = false,
                rmid_wakes_receiver = false,
            );
            return;
        }
        let id = id as i32;
        let mut msg = Msgbuf {
            mtype: 1,
            mtext: [0; 64],
        };
        msg.mtext[..4].copy_from_slice(b"wake");
        let mut got = Msgbuf {
            mtype: 0,
            mtext: [0; 64],
        };

        let empty_rc = msgrcv(id, &mut got, 64, 1, IPC_NOWAIT);
        report!(nowait_empty_enomsg = empty_rc == -1 && errno() == ENOMSG);

        let qbytes_set = set_qbytes(id, 4);
        let first_send = msgsnd(id, &msg, 4, 0);
        let full_rc = msgsnd(id, &msg, 4, IPC_NOWAIT);
        report!(nowait_full_eagain = qbytes_set && first_send == 0 && full_rc == -1 && errno() == EAGAIN);

        let reader = libc::fork();
        if reader == 0 {
            let mut recv = Msgbuf {
                mtype: 0,
                mtext: [0; 64],
            };
            let rc = msgrcv(id, &mut recv, 64, 1, 0);
            libc::_exit((rc == 4 && &recv.mtext[..4] == b"wake") as i32 ^ 1);
        }
        let mut sender_msg = Msgbuf {
            mtype: 1,
            mtext: [0; 64],
        };
        sender_msg.mtext[..4].copy_from_slice(b"next");
        let send_after_reader = msgsnd(id, &sender_msg, 4, 0);
        let mut reader_status = 0;
        libc::waitpid(reader, &mut reader_status, 0);
        report!(fork_reader_wakes_sender = send_after_reader == 0 && child_exited_zero(reader_status));

        let remove_id = msgget(IPC_PRIVATE, IPC_CREAT | 0o600) as i32;
        let receiver = libc::fork();
        if receiver == 0 {
            let mut recv = Msgbuf {
                mtype: 0,
                mtext: [0; 64],
            };
            let rc = msgrcv(remove_id, &mut recv, 64, 1, 0);
            libc::_exit((rc == -1 && errno() == EIDRM) as i32 ^ 1);
        }
        libc::usleep(100_000);
        let rm = msgctl(remove_id, IPC_RMID, core::ptr::null_mut());
        let mut receiver_status = 0;
        libc::waitpid(receiver, &mut receiver_status, 0);
        report!(rmid_wakes_receiver = rm == 0 && child_exited_zero(receiver_status));

        let _ = msgctl(id, IPC_RMID, core::ptr::null_mut());
    }
}
```

- [ ] **Step 2: Run red-first against the current signed binary**

Run:

```bash
just build
target/release/carrick run --raw --fs host localhost:5050/ltp:arm64 /opt/carrick-probes/sysvmsgwake
```

Expected before explicit wait/wake: at least `rmid_wakes_receiver=false` or a timeout. If all keys pass before Task 5, record the passing output in the commit body and keep the probe because it guards the behavior.

- [ ] **Step 3: Register the probe if needed**

If `scripts/conformance/suites.toml` explicitly lists probe binaries, add:

```toml
[[suite]]
name = "probe-sysvmsgwake"
image = "localhost:5050/ltp:arm64"
cmd = ["/opt/carrick-probes/sysvmsgwake"]
expect = "match"
```

If the probe harness auto-discovers `conformance-probes/src/bin/*.rs`, leave `suites.toml` unchanged.

- [ ] **Step 4: Commit**

Run:

```bash
git add conformance-probes/src/bin/sysvmsgwake.rs scripts/conformance/suites.toml
git diff --cached -- conformance-probes/src/bin/sysvmsgwake.rs scripts/conformance/suites.toml
git commit -m "test(conformance): cover sysv message wake paths"
```

Commit body:

```text
The broad LTP stress test was the first place Carrick showed that message queue
blocking and wakeup behavior was not modeled as an explicit service operation.
Add a focused probe for nonblocking empty/full behavior, forked reader/sender
handoff, and IPC_RMID waking a blocked receiver.

Verified:
- just build
- target/release/carrick run --raw --fs host localhost:5050/ltp:arm64 /opt/carrick-probes/sysvmsgwake

Co-Authored-By: Codex <codex@openai.com>
```

---

### Task 4: Introduce Run-Scoped Shared Service Mapping

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs`

**Interfaces:**
- Consumes: `SysvIpcService` from Task 2.
- Produces:
  - `struct SysvMsgServiceMapping`
  - `#[repr(C)] struct SysvMsgServiceHeader`
  - `#[repr(C)] struct SysvMsgQueueSlot`
  - `#[repr(C)] struct SysvMsgRecordHeader`
  - `impl SysvIpcService { fn mapping(&self) -> Result<SysvMsgServiceMapping, LinuxErrno>; }`

- [ ] **Step 1: Add shared layout constants and typed layout wrappers**

Add near the existing message constants:

```rust
const SYSV_MSG_SERVICE_MAGIC: u32 = 0x4356_4d51;
const SYSV_MSG_SERVICE_VERSION: u32 = 1;
const SYSV_MSG_QUEUE_SLOTS: usize = 512;
const SYSV_MSG_ARENA_BYTES: usize = 8 * 1024 * 1024;
const SYSV_MSG_SERVICE_BYTES: usize = std::mem::size_of::<SysvMsgServiceHeader>()
    + std::mem::size_of::<SysvMsgQueueSlot>() * SYSV_MSG_QUEUE_SLOTS
    + SYSV_MSG_ARENA_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MsgQueueSlotIndex(u32);

impl MsgQueueSlotIndex {
    fn from_usize(value: usize) -> Result<Self, LinuxErrno> {
        u32::try_from(value)
            .map(Self)
            .map_err(|_| LINUX_EINVAL)
    }

    fn as_usize(self) -> usize {
        self.0 as usize
    }

    fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MsgArenaOffset(u32);

impl MsgArenaOffset {
    const NONE: Self = Self(u32::MAX);

    fn from_usize(value: usize) -> Result<Self, LinuxErrno> {
        u32::try_from(value)
            .map(Self)
            .map_err(|_| LINUX_EINVAL)
    }

    fn as_usize(self) -> Option<usize> {
        (self != Self::NONE).then_some(self.0 as usize)
    }

    fn raw(self) -> u32 {
        self.0
    }
}
```

- [ ] **Step 2: Add C-layout shared structs**

Add:

```rust
#[repr(C)]
struct SysvMsgServiceHeader {
    magic: std::sync::atomic::AtomicU32,
    version: std::sync::atomic::AtomicU32,
    lock_word: std::sync::atomic::AtomicU32,
    wake_epoch: std::sync::atomic::AtomicU32,
    next_id: std::sync::atomic::AtomicU32,
    live_queues: std::sync::atomic::AtomicU32,
    arena_next: std::sync::atomic::AtomicU32,
    _reserved: [u32; 9],
}

#[repr(C)]
struct SysvMsgQueueSlot {
    state: std::sync::atomic::AtomicU32,
    id: std::sync::atomic::AtomicI32,
    key: std::sync::atomic::AtomicI32,
    mode: std::sync::atomic::AtomicU32,
    uid: std::sync::atomic::AtomicU32,
    gid: std::sync::atomic::AtomicU32,
    cuid: std::sync::atomic::AtomicU32,
    cgid: std::sync::atomic::AtomicU32,
    qbytes: std::sync::atomic::AtomicU64,
    cbytes: std::sync::atomic::AtomicU64,
    qnum: std::sync::atomic::AtomicU64,
    stime: std::sync::atomic::AtomicU64,
    rtime: std::sync::atomic::AtomicU64,
    ctime: std::sync::atomic::AtomicU64,
    lspid: std::sync::atomic::AtomicI32,
    lrpid: std::sync::atomic::AtomicI32,
    head: std::sync::atomic::AtomicU32,
    tail: std::sync::atomic::AtomicU32,
    wait_epoch: std::sync::atomic::AtomicU32,
}

#[repr(C)]
struct SysvMsgRecordHeader {
    msg_type: i64,
    payload_len: u32,
    next: u32,
}
```

- [ ] **Step 3: Add mapping open/create**

Add:

```rust
struct SysvMsgServiceMapping {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
    fd: i32,
}

impl SysvMsgServiceMapping {
    fn open() -> Result<Self, LinuxErrno> {
        SysvShmState::ensure_dir();
        let path = PathBuf::from(SHM_DIR).join(format!("{}-msg-service", sysv_run_scope()));
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| LINUX_EINVAL)?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDWR | libc::O_CREAT,
                0o600,
            )
        }
        .host_syscall_errno()?;
        unsafe { libc::ftruncate(fd, SYSV_MSG_SERVICE_BYTES as libc::off_t) }
            .host_syscall_errno()?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SYSV_MSG_SERVICE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(LINUX_EINVAL);
        }
        let mapping = Self {
            ptr: std::ptr::NonNull::new(ptr.cast::<u8>()).ok_or(LINUX_EINVAL)?,
            len: SYSV_MSG_SERVICE_BYTES,
            fd,
        };
        mapping.initialize_header();
        Ok(mapping)
    }

    fn header(&self) -> &SysvMsgServiceHeader {
        unsafe { &*(self.ptr.as_ptr().cast::<SysvMsgServiceHeader>()) }
    }

    fn slots(&self) -> &[SysvMsgQueueSlot] {
        let base = unsafe {
            self.ptr
                .as_ptr()
                .add(std::mem::size_of::<SysvMsgServiceHeader>())
                .cast::<SysvMsgQueueSlot>()
        };
        unsafe { std::slice::from_raw_parts(base, SYSV_MSG_QUEUE_SLOTS) }
    }

    fn arena_base(&self) -> *mut u8 {
        unsafe {
            self.ptr.as_ptr().add(
                std::mem::size_of::<SysvMsgServiceHeader>()
                    + std::mem::size_of::<SysvMsgQueueSlot>() * SYSV_MSG_QUEUE_SLOTS,
            )
        }
    }

    fn initialize_header(&self) {
        use std::sync::atomic::Ordering;
        let header = self.header();
        if header.magic.load(Ordering::Acquire) == SYSV_MSG_SERVICE_MAGIC {
            return;
        }
        header.version.store(SYSV_MSG_SERVICE_VERSION, Ordering::Release);
        header.next_id.store(1, Ordering::Release);
        header.arena_next.store(0, Ordering::Release);
        header.magic.store(SYSV_MSG_SERVICE_MAGIC, Ordering::Release);
    }
}

impl Drop for SysvMsgServiceMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
            libc::close(self.fd);
        }
    }
}
```

- [ ] **Step 4: Add mapping ownership to `SysvIpcService`**

Change:

```rust
pub(super) struct SysvIpcService {
    mapping: Option<SysvMsgServiceMapping>,
}
```

and:

```rust
    fn new() -> Self {
        Self { mapping: None }
    }

    fn mapping(&mut self) -> Result<&mut SysvMsgServiceMapping, LinuxErrno> {
        if self.mapping.is_none() {
            self.mapping = Some(SysvMsgServiceMapping::open()?);
        }
        self.mapping.as_mut().ok_or(LINUX_EINVAL)
    }

    fn after_fork_child(&mut self) {
        self.mapping = None;
        MSG_QUEUE_FD_CACHE.with(|cache| cache.borrow_mut().refresh_for_current_process());
    }
```

- [ ] **Step 5: Run compile checks**

Run:

```bash
just fmt-check
just check -p carrick-runtime
just lint-domains
```

Expected: all pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/carrick-runtime/src/dispatch/sysv.rs
git diff --cached -- crates/carrick-runtime/src/dispatch/sysv.rs
git commit -m "feat(runtime): add shared sysv message service mapping"
```

Commit body:

```text
SysV message queues need fork-coherent runtime-owned state instead of
per-operation queue-file rewrites. Add the run-scoped shared service mapping
and typed layout wrappers that later queue operations will use.

This commit does not switch the syscall hot path yet; it only establishes the
shared backing region and child refresh behavior so the next commit can move
queue operations behind it with a small review diff.

Verified:
- just fmt-check
- just check -p carrick-runtime
- just lint-domains

Co-Authored-By: Codex <codex@openai.com>
```

---

### Task 5: Move Queue Operations Onto Shared State

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs`

**Interfaces:**
- Consumes: `SysvMsgServiceMapping` and existing message syscall handlers.
- Produces:
  - `SysvIpcService::msgget`
  - `SysvIpcService::msgsnd`
  - `SysvIpcService::msgrcv`
  - `SysvIpcService::msgctl`
  - `SysvIpcService::msg_table`
  - `SysvIpcService::metrics`

- [ ] **Step 1: Add service lock helper**

Add:

```rust
struct SysvMsgServiceGuard<'a> {
    mapping: &'a SysvMsgServiceMapping,
}

impl<'a> SysvMsgServiceGuard<'a> {
    fn lock(mapping: &'a SysvMsgServiceMapping) -> Self {
        use std::sync::atomic::Ordering;
        let lock = &mapping.header().lock_word;
        while lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
        Self { mapping }
    }
}

impl Drop for SysvMsgServiceGuard<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.mapping.header().lock_word.store(0, Ordering::Release);
    }
}
```

This is a temporary correctness lock for the first shared-state cut. Task 6 replaces wait-loop polling with explicit futex wait/wake on `wake_epoch` and per-slot `wait_epoch`.

- [ ] **Step 2: Implement queue slot lookup and allocation**

Add methods on `SysvIpcService`:

```rust
fn find_slot_by_id(mapping: &SysvMsgServiceMapping, id: MsgQueueId) -> Option<MsgQueueSlotIndex> {
    use std::sync::atomic::Ordering;
    mapping.slots().iter().enumerate().find_map(|(idx, slot)| {
        let live = slot.state.load(Ordering::Acquire) == 1;
        let same = slot.id.load(Ordering::Acquire) == id.raw();
        (live && same).then(|| MsgQueueSlotIndex::from_usize(idx).ok()).flatten()
    })
}

fn find_slot_by_key(mapping: &SysvMsgServiceMapping, key: MsgKey) -> Option<MsgQueueSlotIndex> {
    use std::sync::atomic::Ordering;
    if key.is_private() {
        return None;
    }
    mapping.slots().iter().enumerate().find_map(|(idx, slot)| {
        let live = slot.state.load(Ordering::Acquire) == 1;
        let same = slot.key.load(Ordering::Acquire) == key.raw();
        (live && same).then(|| MsgQueueSlotIndex::from_usize(idx).ok()).flatten()
    })
}
```

Add allocation under the service lock:

```rust
fn allocate_slot(
    mapping: &SysvMsgServiceMapping,
    key: MsgKey,
    mode: ShmPermMode,
    creds: &super::creds::CredState,
) -> Result<(MsgQueueSlotIndex, MsgQueueId), LinuxErrno> {
    use std::sync::atomic::Ordering;
    let idx = mapping
        .slots()
        .iter()
        .enumerate()
        .find_map(|(idx, slot)| {
            (slot.state.load(Ordering::Acquire) == 0)
                .then(|| MsgQueueSlotIndex::from_usize(idx).ok())
                .flatten()
        })
        .ok_or(LINUX_ENOSPC)?;
    let id = MsgQueueId(i32::try_from(mapping.header().next_id.fetch_add(1, Ordering::AcqRel))
        .map_err(|_| LINUX_ENOSPC)?);
    let slot = &mapping.slots()[idx.as_usize()];
    let now = unix_now_secs();
    slot.id.store(id.raw(), Ordering::Release);
    slot.key.store(key.raw(), Ordering::Release);
    slot.mode.store(mode.raw(), Ordering::Release);
    slot.uid.store(creds.euid, Ordering::Release);
    slot.gid.store(creds.egid, Ordering::Release);
    slot.cuid.store(creds.euid, Ordering::Release);
    slot.cgid.store(creds.egid, Ordering::Release);
    slot.qbytes.store(LINUX_MSGMNB, Ordering::Release);
    slot.cbytes.store(0, Ordering::Release);
    slot.qnum.store(0, Ordering::Release);
    slot.stime.store(0, Ordering::Release);
    slot.rtime.store(0, Ordering::Release);
    slot.ctime.store(now, Ordering::Release);
    slot.lspid.store(0, Ordering::Release);
    slot.lrpid.store(0, Ordering::Release);
    slot.head.store(MsgArenaOffset::NONE.raw(), Ordering::Release);
    slot.tail.store(MsgArenaOffset::NONE.raw(), Ordering::Release);
    slot.state.store(1, Ordering::Release);
    mapping.header().live_queues.fetch_add(1, Ordering::AcqRel);
    Ok((idx, id))
}
```

- [ ] **Step 3: Implement append and receive using arena records**

Implement append by allocating `SysvMsgRecordHeader + payload` from `arena_next`, writing the record, linking it at `tail`, and updating `cbytes`, `qnum`, `stime`, and `lspid` under `SysvMsgServiceGuard`.

Implement receive by walking from `head`, applying the existing `selected_msg_index` semantics to candidate headers, copying the selected payload into guest memory, unlinking unless `MSG_COPY`, and updating `cbytes`, `qnum`, `rtime`, and `lrpid`.

Preserve these existing semantic checks exactly:

```rust
if !queue.can_write(creds) {
    return Err(LINUX_EACCES);
}
if payload_len.raw() > LINUX_MSGMAX {
    return Err(LINUX_EINVAL);
}
if full_by_bytes || full_by_count {
    return Ok(false);
}
if message.payload.len() > msgsz && !flags.contains(MsgOpFlags::NOERROR) {
    return Err(LINUX_E2BIG);
}
```

- [ ] **Step 4: Route handlers to service methods**

In `msgget`, parse the key with:

```rust
let key = match MsgKey::from_syscall_arg(key) {
    Ok(key) => key,
    Err(errno) => return DispatchOutcome::errno(errno),
};
```

Then call `state.msg_service.msgget(&creds, key, msgflg)`.

For `msgsnd`, keep guest memory copying in the handler, then call service `msgsnd`.

For `msgrcv`, keep guest memory write in the service because receive selection and `MSG_COPY` need to be atomic with queue mutation.

For `msgctl`, call service `msgctl` rather than free `sysv_msgctl`.

- [ ] **Step 5: Run focused checks**

Run:

```bash
just fmt-check
just lint-domains
just check -p carrick-runtime
just build
just conformance-probes
just conformance full --workers 1 --suite ltp-msgctl04 --suite ltp-msgctl06 --suite ltp-msgrcv03 --suite ltp-msgstress01 --flake-retries 0
```

Expected: compile gates pass; existing SysV focused suites should match or expose only missing explicit wait/wake behavior that Task 6 addresses.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/carrick-runtime/src/dispatch/sysv.rs
git diff --cached -- crates/carrick-runtime/src/dispatch/sysv.rs
git commit -m "feat(runtime): store sysv messages in shared service state"
```

Commit body:

```text
The previous message queue hot path rewrote queue files and reparsed messages
for every operation. That preserved fork visibility but made stress workloads
dominated by filesystem serialization instead of queue semantics.

Move queue contents, metadata, and procfs snapshots onto the run-scoped shared
service mapping while preserving the existing typed message selection and
permission checks. This keeps state fork-coherent and removes per-message file
rewrites from the send/receive path.

Verified:
- just fmt-check
- just lint-domains
- just check -p carrick-runtime
- just build
- just conformance-probes
- just conformance full --workers 1 --suite ltp-msgctl04 --suite ltp-msgctl06 --suite ltp-msgrcv03 --suite ltp-msgstress01 --flake-retries 0

Co-Authored-By: Codex <codex@openai.com>
```

---

### Task 6: Replace Polling Waits With Explicit Wake

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs`

**Interfaces:**
- Consumes: `SysvMsgServiceMapping`, `SysvMsgQueueSlot::wait_epoch`, Carrick shared futex host implementation.
- Produces:
  - `fn wait_for_msg_epoch(slot: &SysvMsgQueueSlot, observed: u32, interrupted: &dyn Fn() -> bool) -> Result<(), LinuxErrno>`
  - `fn wake_msg_waiters(slot: &SysvMsgQueueSlot)`
  - Blocking `msgsnd` and `msgrcv` wake on send, receive, and `IPC_RMID`.

- [ ] **Step 1: Add wake helpers**

Add:

```rust
fn wake_msg_waiters(slot: &SysvMsgQueueSlot) {
    use std::sync::atomic::Ordering;
    let next = slot.wait_epoch.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    let addr = (&slot.wait_epoch as *const std::sync::atomic::AtomicU32) as usize;
    let _ = carrick_host::ulock::wake(addr, true);
    let _ = (slot.id.load(Ordering::Acquire), next);
}
```

- [ ] **Step 2: Add bounded epoch wait**

Add:

```rust
fn wait_for_msg_epoch(
    slot: &SysvMsgQueueSlot,
    observed: u32,
    interrupted: &dyn Fn() -> bool,
) -> Result<(), LinuxErrno> {
    let addr = (&slot.wait_epoch as *const std::sync::atomic::AtomicU32) as usize;
    loop {
        if interrupted() {
            return Err(LINUX_EINTR);
        }
        let current = slot.wait_epoch.load(std::sync::atomic::Ordering::Acquire);
        if current != observed {
            return Ok(());
        }
        let rc = carrick_host::ulock::wait(addr, observed, 20_000);
        if rc == 0 || rc == -(libc::ETIMEDOUT as i64) || rc == -(libc::EINTR as i64) {
            continue;
        }
        return Ok(());
    }
}
```

- [ ] **Step 3: Wire blocking send and receive**

Change blocking `msgsnd` loop to:

```rust
let observed = slot.wait_epoch.load(std::sync::atomic::Ordering::Acquire);
drop(guard);
wait_for_msg_epoch(slot, observed, &|| sysv_msg_wait_interrupted(this, tid))?;
```

Change successful receive, successful send, and `IPC_RMID` to call `wake_msg_waiters(slot)` after mutation.

Change `IPC_RMID` state transition to mark the slot removed before waking:

```rust
slot.state.store(2, std::sync::atomic::Ordering::Release);
wake_msg_waiters(slot);
```

Blocked waiters that wake and observe state `2` return `LINUX_EIDRM`.

- [ ] **Step 4: Run red probe and SysV LTP cluster**

Run:

```bash
just fmt-check
just lint-domains
just check -p carrick-runtime
just build
target/release/carrick run --raw --fs host localhost:5050/ltp:arm64 /opt/carrick-probes/sysvmsgwake
just conformance full --workers 1 --suite ltp-msgctl01 --suite ltp-msgctl02 --suite ltp-msgctl03 --suite ltp-msgctl04 --suite ltp-msgctl06 --suite ltp-msgctl12 --suite ltp-msgget01 --suite ltp-msgget02 --suite ltp-msgget04 --suite ltp-msgget05 --suite ltp-msgrcv01 --suite ltp-msgrcv02 --suite ltp-msgrcv03 --suite ltp-msgrcv05 --suite ltp-msgrcv06 --suite ltp-msgrcv07 --suite ltp-msgrcv08 --suite ltp-msgsnd01 --suite ltp-msgsnd02 --suite ltp-msgsnd05 --suite ltp-msgsnd06 --suite ltp-msgstress01 --flake-retries 0
```

Expected: probe reports all keys true; focused SysV LTP cluster matches Docker oracle.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/carrick-runtime/src/dispatch/sysv.rs
git diff --cached -- crates/carrick-runtime/src/dispatch/sysv.rs
git commit -m "fix(runtime): wake sysv message waiters explicitly"
```

Commit body:

```text
Blocking SysV message operations should sleep on queue state transitions, not
poll with host sleeps. Polling made wakeup latency and IPC_RMID behavior depend
on scheduler timing and kept the stress path expensive.

Add an explicit per-queue epoch wake path for send, receive, and removal. A
blocked sender wakes when capacity changes, a blocked receiver wakes when a
matching message might exist, and IPC_RMID wakes waiters to return EIDRM.

Verified:
- just fmt-check
- just lint-domains
- just check -p carrick-runtime
- just build
- target/release/carrick run --raw --fs host localhost:5050/ltp:arm64 /opt/carrick-probes/sysvmsgwake
- focused SysV LTP cluster listed in the implementation plan

Co-Authored-By: Codex <codex@openai.com>
```

---

### Task 7: Final SysV and Goal Gates

**Files:**
- Modify only files whose verification exposes real defects.

**Interfaces:**
- Consumes: All prior tasks.
- Produces: Verified focused SysV cluster and then progress against `docs/2026-07-03-bless-regressions.md`.

- [ ] **Step 1: Run focused trace if `msgstress01` still times out**

Run:

```bash
export CARRICK_RUN_ID=sysv-msgstress-trace-$(date +%s)-$$
scripts/sudo/kill.sh "$CARRICK_RUN_ID" || true
timeout 90 target/release/carrick trace --script scripts/dtrace/msgstress-sysv.d --trace-out /tmp/carrick-msgstress-sysv.out -- run --name "$CARRICK_RUN_ID" --raw --fs host localhost:5050/ltp:arm64 /opt/ltp/testcases/bin/msgstress01
scripts/sudo/kill.sh "$CARRICK_RUN_ID" || true
```

Expected: trace shows balanced `msgsnd` and `msgrcv` progress. If it shows a new stall, root-cause that stall before changing code.

- [ ] **Step 2: Run focused SysV cluster**

Run:

```bash
just conformance full --workers 1 --suite ltp-msgctl01 --suite ltp-msgctl02 --suite ltp-msgctl03 --suite ltp-msgctl04 --suite ltp-msgctl06 --suite ltp-msgctl12 --suite ltp-msgget01 --suite ltp-msgget02 --suite ltp-msgget04 --suite ltp-msgget05 --suite ltp-msgrcv01 --suite ltp-msgrcv02 --suite ltp-msgrcv03 --suite ltp-msgrcv05 --suite ltp-msgrcv06 --suite ltp-msgrcv07 --suite ltp-msgrcv08 --suite ltp-msgsnd01 --suite ltp-msgsnd02 --suite ltp-msgsnd05 --suite ltp-msgsnd06 --suite ltp-msgstress01 --flake-retries 0
```

Expected: all listed suites match Docker oracle.

- [ ] **Step 3: Run broad gate required by the active goal**

Run:

```bash
just conformance full --workers 1 --flake-retries 0
just ci
```

Expected: all re-bless suites in `docs/2026-07-03-bless-regressions.md` match Docker oracle and `just ci` passes.

- [ ] **Step 4: Commit a support matrix update only when verification changes it**

When `just conformance full` changes `docs/support-matrix.md`, commit that tracked artifact separately:

```bash
git add docs/support-matrix.md
git diff --cached -- docs/support-matrix.md
git commit -m "docs(conformance): record sysv ipc verification"
```

Commit body:

```text
Record the post-fix verification artifact generated from the fresh conformance
run. No baselines or known gaps were added.

Verified:
- just conformance full --workers 1 --flake-retries 0
- just ci

Co-Authored-By: Codex <codex@openai.com>
```

---

## Self-Review

- Spec coverage:
  - Runtime-owned SysV IPC service: Tasks 2, 4, 5, and 6.
  - Fork-coherent state: Tasks 4 and 5.
  - No `/proc/sys/kernel/threads-max` shaping: Task 1.
  - Typed values and bitflags: Tasks 2, 4, and 5 add `MsgKey`, `MsgBytes`, `MsgQueueSlotIndex`, and `MsgArenaOffset` while preserving `MsgOpFlags`.
  - Procfs/sysctl service source: Task 5 routes `/proc/sysvipc/msg` through the service; existing `msgmax`, `msgmnb`, and `msgmni` remain Carrick-enforced constants.
  - Explicit wait/wake: Task 6.
  - Deterministic probes: Task 3.
  - Focused SysV LTP and full goal gates: Task 7.
- Placeholder scan:
  - No `TBD`, `TODO`, `maybe`, `implement later`, or unspecified test steps remain.
- Type consistency:
  - `MsgKey`, `MsgBytes`, `MsgQueueSlotIndex`, and `MsgArenaOffset` are defined before use.
  - `SysvIpcService` exists before later tasks add behavior.
  - `SysvMsgServiceMapping` owns mmap lifetime and is refreshed after fork.
