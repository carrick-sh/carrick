# carrick namespaces design: UID/GID + PID

**Status:** revised design (incorporating macOS primitive research and NsSupervisor architecture). **Scope:** Linux user (UID/GID) namespaces and PID namespaces, for Docker compatibility. **Network namespaces are explicitly out of scope and are not designed here.**

> **Clean-room note.** Every Linux semantic in this document is derived from man pages
> (`user_namespaces(7)`, `pid_namespaces(7)`, `namespaces(7)`, `clone(2)`, `unshare(2)`,
> `setns(2)`, `credentials(7)`, `capabilities(7)`) and from *observed* behavior of Docker
> + `unshare`/`strace` on a real Linux box. No Linux kernel source, UAPI headers, or
> libc source were read. Every constant cited below is annotated as man-page-documented
> or observed; none came from a header. No macOS kernel source was used; Darwin/XNU behaviors
> were researched using public Apple documentation, man pages, and runtime probe observations.

---

## 1. Goal and scope

carrick runs unmodified Linux aarch64 ELF binaries on macOS. Each guest *process* is a
real macOS host process; guest Linux syscalls are emulated by the Rust dispatcher.

### 1.0 The primary goal: *run a container that is placed in* uid+pid namespaces

The objective is to **run containers that live inside a uid and pid namespace** — not, in
the first instance, to fully implement the namespace-*manipulating* syscalls
(`unshare(2)`/`setns(2)`/`clone(CLONE_NEW*)`) for arbitrary guest use. This distinction
drives the whole priority order, because of *who* creates the namespaces:

- **Docker/`runc` sets up the namespaces from OUTSIDE the container, before the container
  process exists.** `runc` does the `clone(CLONE_NEWPID|CLONE_NEWUSER|...)` / `unshare` /
  map-writing itself, then `execve`s the container entrypoint *already inside* the finished
  namespaces. The container's own processes overwhelmingly just **observe** the result:
  "I am pid 1", "my uid is 0 (mapped)", "`/proc` shows only my containers's processes",
  "`/proc/self/uid_map` reads thus". They rarely create *further* namespaces.
- Therefore carrick's job for Docker compatibility is mostly to **present a correct
  namespace VIEW**, not to be a faithful namespace-creation engine. carrick is the thing
  *playing the role of runc* here: when carrick's `run` frontend launches a guest, it can
  decide "this guest's root process is pid 1 of a fresh pid ns and uid 0 of an identity
  user ns" and set up the translation/view accordingly — entirely on carrick's side,
  without the guest ever issuing a namespace syscall. The guest binary (bash, the app,
  tini) then sees the expected pid 1 / mapped uid, which is what actually matters for
  "can carrick run this container".
- **Full guest-facing `unshare`/`setns`/`clone(CLONE_NEW*)` support is a long-haul
  nice-to-have** (the user is "curious about it in the long haul"). It matters only for
  guests that create their *own* nested namespaces (apt's sandbox, bubblewrap, rootless
  buildkit, systemd-nspawn-in-container). It is deferred to the last phase and is not on
  the critical path for running ordinary container images.

So read the rest of this document with that lens: §4/§5 design the *view and translation*;
the syscall handlers for `unshare`/`setns` (§5.5, §6.6, Phase 4) are the optional long-haul
layer. The carrick-side "place the root guest in these namespaces at launch" wiring (which
needs no guest syscall at all) is the actually-load-bearing part and is called out in §5.2
and Phase 2.

### 1.1 What carrick must emulate (Docker-image lens)

Docker's `runc` always puts a container in a fresh PID namespace and (in the common
rootful case) relies on the user-namespace machinery being *present and consistent* even
when it uses an identity map. What we must emulate, prioritized by what real Docker images
touch:

1. **UID/GID namespace surface** — `/proc/[pid]/uid_map`, `gid_map`, `setgroups`
   readable and writable with the kernel's one-shot/≤5-line/setgroups-gate rules; the
   "uid 0 inside maps to a non-root host uid" model; `getuid/geteuid/...` reflecting the
   in-namespace ids; a full capability set inside a freshly-created userns.
2. **PID namespace surface** — a translation layer (host pid ↔ guest-ns pid) so that
   `getpid` returns 1 for the container init, `/proc` shows only namespace members,
   `getppid`/`wait4`/`kill`/`clone`-return all speak ns-local pids, and pid-1 init
   semantics (orphan reaping, signal defaults, ns teardown on pid-1 exit) hold.
3. The `CLONE_NEWUSER|CLONE_NEWPID` combination (Docker's typical combo) and the
   `unshare(2)`/`setns(2)` entry points.

Out of scope: network, mount (beyond what already exists), UTS, IPC, cgroup, and time
namespaces. Where `clone`/`unshare` request those flags we will accept-and-ignore (treat
the guest as already being in a private instance) rather than `EINVAL`, since rejecting
them breaks container inits — see §6.

### 1.2 What Docker actually does by default (observed)

Run on this host (Docker Desktop / `debian:stable`):

```
$ docker run --rm debian:stable sh -c 'cat /proc/self/uid_map; cat /proc/self/setgroups; \
      readlink /proc/self/ns/pid; readlink /proc/self/ns/user; id; \
      grep -iE "^(Pid|CapEff|CapBnd):" /proc/self/status'
         0          0 4294967295        # uid_map: IDENTITY map (0→0, range 2^32)
allow                                   # setgroups gate is "allow"
pid:[4026532684]                        # a FRESH pid namespace (differs from host init)
user:[4026531837]                       # the HOST initial user ns — NO new userns
uid=0(root) gid=0(root) groups=0(root)
Pid:    1                               # container init is pid 1
CapEff: 00000000a80425fb               # the Docker default bounded capability set (observed)
CapBnd: 00000000a80425fb
```

Conclusions that shape the design:

- **Default rootful Docker does NOT create a new user namespace.** The container shares
  the host's *initial* user ns; the uid_map is the identity map `0 0 4294967295`; the
  container is genuinely (host-)root. So for the **common case carrick already matches**:
  guest uid 0 == host identity, `id` reports `uid=0`. The userns *work* we need is mostly
  to make `/proc/self/{uid_map,gid_map,setgroups}` *exist and read consistently* and to
  honor an *explicit* userns (`docker run --userns=...`, rootless Docker, or a guest that
  `unshare(CLONE_NEWUSER)`s itself — e.g. `apt`'s sandbox, `bubblewrap`, nested buildkit).
- **Default Docker DOES create a fresh PID namespace** (the `pid:[...]` inode differs
  from host init, and `Pid: 1`). carrick today reports `getpid()` = the host pid, *not*
  1. This is the real gap: programs that assume they are pid 1 (tini, dumb-init, `bash`
  as ENTRYPOINT, anything that `kill -0 1`s or reads `/proc/1/...`) misbehave.
- `--user 1000:1000` changes creds but keeps the identity uid_map (no new userns). So our
  existing `setresuid`-tracking creds model already covers `--user`.
- CapEff/CapBnd in a default container is a specific bounded set (observed
  `0x00000000a80425fb`), **not** all-ones and **not** zero. carrick's `/proc/self/status`
  currently hardcodes `CapEff: 0` — a divergence to fix (§4.4).

---

## 2. Current carrick model (what exists today)

### 2.1 PID presentation: guest pid == host pid

carrick forks each guest process as a real macOS process, so *the host process tree
mirrors the guest tree*. Guest pid is currently the **host pid** (`std::process::id()`):

- `crates/carrick-runtime/src/dispatch/creds.rs:167` `getpid()` → `std::process::id()`.
- `creds.rs:530` `sys_getppid` → `LINUX_BOOTSTRAP_PID` (=1) for the root guest, else host
  `libc::getppid()` (because the host tree mirrors the guest tree).
- `crates/carrick-abi/src/lib.rs:1746` `LINUX_BOOTSTRAP_PID: u64 = 1` — a *single* stable
  "init" alias already used in many self-checks (`proc.rs:39`, `signal.rs`, `creds.rs`).
- `crates/carrick-host/src/host_proc.rs` is the crux: `is_guest_process(pid)` walks a
  pid's **host ppid chain** up to `ROOT_GUEST_PID` to decide whether it is one of our own
  guest descendants; `pid_info(pid)` reads identity/state from the host kernel
  (`proc_pidinfo`). `set_root_guest_pid()` records the root guest's host pid at startup
  (`runtime.rs:1937`, `vfs/proc.rs:964`).
- `crates/carrick-hvf/src/thread.rs`: `ThreadId = i32`; `ThreadRegistry.next_tid` is an
  `AtomicI32` seeded at `main_tid + 1` and bumped per thread (`register_child`). tids are
  per-process, *above* the main tid (which equals the host pid). Threads are an
  in-process concern; this registry does NOT cross fork.
- `wait4` (`proc.rs:1302`) and `kill`/`tgkill` (`signal.rs`) pass the guest-supplied pid
  **straight to the host** `libc::wait4`/`libc::kill`. This works only because guest pid
  == host pid today.
- `/proc` enumeration (`vfs/proc.rs:243` `enumerate_guest_pids`) lists *all host pids*
  filtered by `is_guest_process`, and `/proc/[pid]/{stat,status,...}` are synthesized
  from `host_proc::pid_info`. `/proc/self/status` (`vfs/proc.rs:635`) prints
  `Pid: std::process::id()` and hardcodes `Uid: 0 0 0 0`, `CapEff: 0`.

**Implication:** a PID namespace is a *translation layer* over this host-pid reality. The
host process tree (and `host_proc`'s ppid-walk) is exactly the substrate we need; we add a
host-pid ↔ ns-pid map and route every pid-bearing syscall through it.

### 2.2 Credentials: tracked, host runs as root

`crates/carrick-runtime/src/dispatch/creds.rs` already has a per-process `CredState`
(ruid/euid/suid, rgid/egid/sgid, fsuid/fsgid, umask), defaulting to **all zero (root)**.
`set*uid/set*gid` implement the documented transition rules (`mod setid`), gated on
`is_privileged() == (euid == 0)` — i.e. carrick *models CAP_SETUID/CAP_SETGID as "euid
0"*. `getuid/...` echo the tracked values (`sys_getuid` etc.). `cred_ipc.rs` publishes
the current euid to a `/tmp/carrick-cred-<host_pid>` file so peers can see it. This is the
identity-map case already; the missing piece is the *mapping table* an explicit userns
introduces, plus capabilities and the `/proc` map files.

CredState is **per-process in-memory** (`Arc<Mutex<…>>` inside the dispatcher). It is
fork-coherent *only* because fork copies the address space — a child sees the parent's
creds at fork time, and divergence after fork is correct (each process has its own creds).
A **namespace**, by contrast, is *shared* among all members and must be coherent across
fork; in-memory-copied-at-fork is the wrong storage for it (see §6.3).

### 2.3 clone flags: namespace flags not parsed

`crates/carrick-abi/src/lib.rs:1885` `LinuxCloneFlags` defines VM/FS/FILES/SIGHAND/PIDFD/
THREAD/SETTLS/PARENT_SETTID/CHILD_*TID only. It does **not** define `CLONE_NEWUSER`,
`CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWCGROUP`. `clone3`
(`proc.rs:346`) validates flag bits against `CLONE3_VALID_FLAGS = 0x0000_0007_FFFF_FF00`
which *does* span the namespace flag bits (so clone3 with a NEW* flag is accepted today
but silently ignored — it forks an ordinary child). Legacy `clone` (`proc.rs:1431`) only
inspects the thread mask. `unshare(2)` (nr 97) and `setns(2)` (nr 268) are **not in the
dispatch table** (`dispatch/mod.rs`) and currently return `ENOSYS` (catalogued
`Deferred` in `carrick-hvf/src/syscall.rs:244,414`).

Namespace-flag constants we will add (man-page `clone(2)` values, NOT from headers):
`CLONE_NEWNS=0x00020000`, `CLONE_NEWCGROUP=0x02000000`, `CLONE_NEWUTS=0x04000000`,
`CLONE_NEWIPC=0x08000000`, `CLONE_NEWUSER=0x10000000`, `CLONE_NEWPID=0x20000000`,
`CLONE_NEWNET=0x40000000` (NEWNET parsed only to reject/ignore — net ns is out of scope).

### 2.4 /proc backing

`crates/carrick-runtime/src/vfs/proc.rs` synthesizes `/proc`. `PROC_PID_FILES` =
`["cmdline","comm","stat","status"]`. There are **no** `uid_map`/`gid_map`/`setgroups`
files and **no** `ns/` directory. `/proc/self/status` is a fixed template with
`Uid: 0 0 0 0`, `CapEff: 0`, `Pid: <host pid>`. This is the surface the userns + pid-ns
work must extend.

---

## 3. The NsSupervisor: namespace lifecycle orchestrator

### 3.1 Why a dedicated orchestrator

On Linux the kernel handles every dimension of PID namespace lifecycle: allocating
ns-local pids, reparenting orphans to ns-init, routing signals into and out of the
namespace, and tearing down all members when pid 1 exits. This is kernel infrastructure
with no macOS equivalent:

- **No kernel namespaces.** macOS has no `CLONE_NEWPID`, no `/proc/[pid]/ns/`, no
  namespace inode. Every namespace effect is synthesized by carrick's syscall dispatcher.
- **No subreaper.** Linux's `prctl(PR_SET_CHILD_SUBREAPER)` (man page `prctl(2)`) lets a
  process elect itself as the reparenting target for all orphaned descendants.  macOS has
  no equivalent — orphans are reparented to `launchd` (host pid 1), not to the guest
  ns-init. This makes orphan reparenting (§3.6) the hardest gap.
- **No `NOTE_TRACK`.** `kqueue(2)` once offered `NOTE_TRACK` to auto-propagate
  `EVFILT_PROC` watches across `fork`. Apple deprecated it in Mac OS X 10.5 and it is
  documented as non-functional on modern Darwin. Each new namespace member must be
  individually registered with `EVFILT_PROC`/`NOTE_EXIT` — there is no way to say "watch
  all descendants." (The existing `register_child_exit_watch` in
  `carrick-hvf/src/host_signal.rs:200` already arms per-pid watches for exactly this
  reason.)

The original design (now §5.6) distributed these responsibilities across every guest process's
syscall dispatcher, coordinated via `/tmp` files: each guest fork writes an `O_EXCL` file,
each `getppid` re-derives membership from the host tree, each `wait4` scans for orphans.
This is fragile — there is no single place that knows "member X died" before launchd
reaps its zombie, and no way to atomically flag orphans before the next `getppid` call
from a surviving child.

A **single NsSupervisor process** centralizes lifecycle management. It watches every
namespace member via `EVFILT_PROC`, detects death immediately (before launchd reaps the
zombie), updates shared-memory orphan flags, and triggers namespace teardown when pid 1
exits. This is the microkernel model: a small server process providing OS services
(namespace lifecycle) to unprivileged clients (guest processes running in HVF), exactly
as Mach provides IPC/VM to userspace servers on macOS itself.

> The NsSupervisor manages one or more `PidNs` instances per run — a single process
> holding a `HashMap<NsId, PidNs>`. Nested namespaces (Phase 4 — guest-created via
> `clone(CLONE_NEWPID)` or `unshare(CLONE_NEWPID)`) add entries to the map; they do NOT
> spawn additional NsSupervisor processes.

### 3.2 Process topology: parent-of-init

The NsSupervisor is created by forking the runtime process at the existing
`set_root_guest_pid` call site (`runtime.rs:1937`). The **parent** becomes the
NsSupervisor: it enters a kqueue management loop and never runs guest code. The **child**
continues into the HVF loop as the guest-init (ns-pid 1).

This mirrors the `interactive_supervisor.rs` pattern precisely:
`fork_runtime_under_current_process` (`interactive_supervisor.rs:101`) forks a child that
becomes the runtime, while the parent stays in a relay-and-wait loop
`relay_and_wait_in_supervisor` (`interactive_supervisor.rs:210`). The NsSupervisor fork
uses the same structure — parent supervises, child executes — at a lower level in the
process tree.

**Non-interactive mode:**

```
carrick-cli
  └── NsSupervisor              (the runtime fork parent: kqueue loop, no vCPU)
        └── guest-init [ns-pid 1]   (the runtime fork child: HVF loop)
              ├── child [ns-pid 2]
              └── child [ns-pid 3]
```

**Interactive mode:**

```
carrick-cli
  └── launcher                  (fork_launcher_supervisor, interactive_supervisor.rs:73)
        └── interactive-supervisor  (pty session leader, relay loop)
              └── NsSupervisor      (the namespace fork: kqueue loop, no vCPU)
                    └── guest-init [ns-pid 1]   (HVF loop, owns slave pty)
                          ├── child [ns-pid 2]
                          └── child [ns-pid 3]
```

**Why parent-of-init:**

1. **`waitpid` works naturally.** The NsSupervisor is the direct parent of guest-init, so
   it can `waitpid(init_pid, ...)` — no need for `EVFILT_PROC` to detect init's death; the
   standard POSIX parent-child reap path handles it.
2. **Interactive supervisor is unchanged.** The interactive supervisor
   `wait_for_runtime_child` (`interactive_supervisor.rs:262`) sees the NsSupervisor as "the
   runtime child" — the same pid it would have waited on without namespaces. No interactive
   supervisor code needs to change.
3. **Exit status propagation is free.** The NsSupervisor `waitpid`s guest-init, then exits
   with guest-init's exit status. The interactive supervisor (or `carrick-cli` in
   non-interactive mode) reaps the NsSupervisor and gets the same exit code. The parent
   chain is: `carrick-cli → [launcher → interactive-supervisor →] NsSupervisor → guest-init`,
   with exit status propagating right to left.

**`run-elf` mode:** The NsSupervisor is **skipped entirely**. `run-elf` is the
single-process, no-fork path `run_elf_from_dispatcher_debug` (`runtime.rs:361`) — it calls
neither `set_root_guest_pid` nor `init_child_table`. The NsSupervisor fork is gated on
namespace configuration being present (i.e. a `PidNs` was requested at launch). Zero
overhead for non-namespace mode.

### 3.3 Shared state: the MAP_SHARED region

The NsSupervisor allocates a `MAP_SHARED|MAP_ANON` region **before** the fork, using the
same pattern as `guest_cpu::init_child_table` (`carrick-host/src/guest_cpu.rs:112`): a
`libc::mmap(MAP_SHARED|MAP_ANON)` call whose result is stored in a static `AtomicPtr`,
inherited by all fork descendants automatically (the forked child's address space contains
the same pointer to the same physical pages — writes by any process are immediately
visible to all others).

The region contains:

```text
struct NsSharedRegion {
    // --- Per-namespace state (one instance per NsId; initially one) ---
    next_pid: AtomicU32,                    // monotonic ns-pid allocator, starts at 2
                                            // (pid 1 is pre-assigned to init)
    // --- Per-member slots (fixed-size array, MEMBER_SLOTS entries) ---
    members: [MemberSlot; MEMBER_SLOTS],    // e.g. 1024 slots
}

#[repr(C)]
struct MemberSlot {
    host_pid: AtomicU32,     // 0 = free; non-zero = occupied
    ns_pid:   AtomicU32,     // the ns-local pid
    parent_host_pid: AtomicU32,  // host pid of the ns-parent (for orphan detection)
    flags:    AtomicU8,      // MEMBER_ALIVE=0, MEMBER_ORPHANED=1, MEMBER_DEAD=2
    exit_status: AtomicI32,  // exit status (set by NsSupervisor on NOTE_EXIT)
}
```

**Why `AtomicU32` in `MAP_SHARED` works cross-process.** Hardware atomics on Apple Silicon
(and on x86_64) operate on **physical addresses**, not virtual: the CPU's exclusive monitor
(LDAXR/STLXR pair on AArch64, lock-prefixed instructions on x86_64) tracks the cache line
in the L1/L2 hierarchy, which is identified by physical address. Two processes mapping the
same `MAP_SHARED` page see the same physical page; an `AtomicU32::fetch_add(1, SeqCst)` in
one process is visible to, and correctly sequenced with, an atomic load in another. This is
verified: `AtomicU32::is_lock_free()` returns `true` on all Apple Silicon (M1 through M4),
confirming the compiler emits hardware atomics, not a fallback `pthread_mutex`-based
emulation.

The existing `guest_cpu.rs` child table (`ChildSlot`, `guest_cpu.rs:101`) already relies on
exactly this property: `AtomicU64` fields in a `MAP_SHARED` region are read and written
from both parent and child processes with `compare_exchange` and `store`/`load`.

**Why NOT other synchronization primitives:**

| Primitive | Problem on macOS |
|---|---|
| `os_unfair_lock` | Not documented as safe cross-process; no `PTHREAD_PROCESS_SHARED` equivalent. The lock state is per-address-space; a lock held in one process is invisible to another mapping the same page. |
| `pthread_mutex` with `PTHREAD_PROCESS_SHARED` | macOS does not implement `PTHREAD_MUTEX_ROBUST` (documented: `pthread_mutexattr_setrobust` returns `ENOTSUP`). If a process holding the mutex is killed (`SIGKILL`), the mutex is permanently locked — every other process deadlocks. Unacceptable for a namespace where members are routinely killed. |
| Named semaphores (`sem_open`) | Leaked on crash: if the owning process dies without `sem_unlink`, the semaphore persists in `/dev/shm` (or the kernel) until the next reboot. Cleanup is unreliable. |
| File locks (`flock`/`fcntl`) | Released on any `close()` of *any* fd referencing the file (not just the locking fd) — a footgun in a codebase that `dup2`s and closes fds freely. Also serializes the hot path (every `getpid`/`getppid` would contend). |

Lock-free atomics avoid all of these: no holder, no crash-leak, no contention on read-only
paths.

**Relationship to the file-based store.** The MAP_SHARED region **supplements**, not
replaces, the `O_EXCL` file store under `/tmp/carrick-ns-<root>/`. Write-once data —
`uid_map`/`gid_map` entries, the canonical `ns_pid→host_pid` record — still uses files
(e.g. `/tmp/carrick-ns-<root>/pid/<ns_id>/<ns_pid>` containing the host pid). Files
provide debuggability (`ls /tmp/carrick-ns-*/pid/` shows namespace membership), crash
visibility (survives the NsSupervisor's death for post-mortem), and the existing
`cred_ipc.rs`-style (`cred_ipc.rs:1`) pattern. The MAP_SHARED region handles the **mutable
hot-path** state: the `next_pid` allocator, the orphan flags (written by NsSupervisor, read
by every `getppid` dispatcher), and the dead-member exit statuses (read by init's `wait4`).

### 3.4 The NsSupervisor event loop

The NsSupervisor does **not** run guest code. It has no HVF context, no vCPU, and
executes no Linux syscalls. It is a pure macOS process running a kqueue-based event loop,
structurally similar to the interactive supervisor's `relay_and_wait_in_supervisor`
(`interactive_supervisor.rs:210`) but watching namespace members instead of pty I/O.

The event loop processes three event sources on a single kqueue:

1. **`EVFILT_PROC`/`NOTE_EXIT` — member death watches.**  One watch per namespace member,
   registered via the existing `darwin_kqueue::Kevent::proc_exit(pid)` helper
   (`darwin_kqueue.rs:123`). When a member exits, the kqueue delivers an event carrying the
   pid (`Kevent::proc_exit_ident`, `darwin_kqueue.rs:177`). The watch is `EV_ONESHOT`
   (auto-removed on fire). Since `NOTE_TRACK` is deprecated and non-functional on modern
   macOS, watches cannot auto-propagate to children; each new member must be individually
   registered (§3.5).

2. **`EVFILT_READ` on a registration pipe.**  A pipe created before the NsSupervisor fork.
   New namespace members write a single notification byte (non-blocking) after
   self-registering in the MAP_SHARED region. The `EVFILT_READ` event wakes the
   NsSupervisor, which scans the shared member table for new entries and arms
   `EVFILT_PROC`/`NOTE_EXIT` for each.

3. **`EVFILT_PROC`/`NOTE_EXIT` on guest-init (the NsSupervisor's own child).**  Detected
   via the standard `waitpid` return — no additional kqueue registration needed, since
   init is the NsSupervisor's direct child. Init death is the namespace teardown trigger.

**On member death:**

```
EVFILT_PROC fires for host_pid P
  → look up P in the shared member table
  → for each live member whose parent_host_pid == P:
      set flags = MEMBER_ORPHANED (AtomicU8 store, Release)
  → set members[P].flags = MEMBER_DEAD
  → harvest exit status from NOTE_EXITSTATUS (the kqueue `data` field)
    and store into members[P].exit_status
```

**On init death:**

```
waitpid(init_pid) returns
  → namespace teardown:
    1. killpg(ns_pgid, SIGKILL)       // fast atomic path: kill the whole
                                       // process group in one syscall
    2. for each members[i] where flags != MEMBER_DEAD:
         kill(members[i].host_pid, SIGKILL)   // sweep: catch any member
                                               // that escaped via setpgid/setsid
    3. drain remaining EVFILT_PROC events (they arrive as the killed members die)
    4. mark the PidNs as dead
  → exit with init's exit status
```

The `killpg` + individual-`kill` sweep mirrors how the Linux kernel tears down a pid
namespace: first the process group (the common case — most children inherit the init's
pgid), then any process that called `setpgid`/`setsid` to leave the group (documented:
`setsid(2)` creates a new session and process group, escaping the original pgid).

**Race-freedom of `EVFILT_PROC` registration.** macOS kqueue guarantees (observed) that if
a pid has already exited at the time `kevent(EV_ADD, EVFILT_PROC, NOTE_EXIT)` is called,
the event fires immediately (or `kevent` returns `EV_ERROR` with `ESRCH`). Either way the
NsSupervisor learns of the death. There is no window where a member could die unobserved
between its fork and its `EVFILT_PROC` registration — the kqueue catches up. The existing
comment in `host_signal.rs:222` documents this property: "ENOENT (the child already exited
and was reaped before we armed) is fine."

### 3.5 Member registration protocol

When a guest process forks a child into a namespace (the `DispatchOutcome::Fork` path at
`runtime.rs:657`), the **child** self-registers:

```
 1. Child inherits the MAP_SHARED region (automatic via fork — same pointer,
    same physical pages, same as guest_cpu child table inheritance).

 2. Allocate ns-pid:
      ns_pid = shared.next_pid.fetch_add(1, SeqCst)
    O(1), lock-free, guaranteed unique (monotonic, no recycle).  The counter
    is seeded at 2 (pid 1 was pre-assigned to init before the NsSupervisor
    fork).

 3. Find a free slot in the shared member table:
      scan members[] for host_pid == 0
      CAS(members[i].host_pid, 0, self_host_pid)
    Write ns_pid, parent_host_pid, flags=MEMBER_ALIVE.

 4. Create the durable O_EXCL file:
      /tmp/carrick-ns-<root>/pid/<ns_id>/<ns_pid>
    containing the host_pid (4 bytes LE).  This is the write-once canonical
    record — survives crashes, visible to debuggers, matches the §4.6 design.

 5. Write a single notification byte to the registration pipe (non-blocking
    write(2) on the inherited pipe fd).  If the pipe is full (pathological:
    64KB of unread notifications), the write returns EAGAIN — acceptable,
    because the NsSupervisor also does a periodic scan (step 6b).

 6. NsSupervisor wakes on EVFILT_READ:
    (a) Drains the pipe (read all pending bytes — one per new member).
    (b) Scans the shared member table for entries not yet watched
        (tracked via a local seen-set keyed on slot index).
    (c) Arms EVFILT_PROC/NOTE_EXIT for each new host_pid.
```

**Crash between steps 2 and 6.** If the child dies after allocating the ns-pid (step 2)
but before the NsSupervisor arms its watch (step 6c):

- **If step 3 completed:** The NsSupervisor's periodic scan (on any subsequent wake) finds
  the entry. When it calls `kevent(EV_ADD, EVFILT_PROC, NOTE_EXIT, host_pid)`, macOS
  returns the exit event immediately (the pid is already dead). The NsSupervisor marks the
  slot MEMBER_DEAD. Correct.
- **If step 3 did NOT complete:** The ns-pid was allocated (the counter advanced) but no
  slot was written. The pid is "wasted" — a gap in the namespace's pid sequence. This is
  acceptable: the §4.6/§7 design already notes that pid recycling is deferred, and gaps in
  a monotonic allocator are harmless (no other member will ever receive the same ns-pid).
- **If step 5 did NOT complete** (pipe write never happened): The NsSupervisor does not get
  a wake for this specific member. It discovers the entry on its next wake from any other
  event (another member registration, another member death, or a periodic 1-second timeout
  on the kqueue). The member's death is still caught via `EVFILT_PROC` once armed, or via
  the immediate-fire property if the member is already dead.

### 3.6 Orphan reparenting emulation

The hardest macOS gap: no subreaper. When a guest parent dies, macOS reparents its host
children to `launchd` (host pid 1), not to ns-init. The guest child's real host `ppid`
becomes 1 (launchd), which is not a namespace member and is not the ns-init. A raw
`libc::getppid()` would return a nonsensical value from the namespace's perspective.

The NsSupervisor solves this entirely in userspace:

**Step 1 — detect parent death.** `EVFILT_PROC`/`NOTE_EXIT` fires for the dead parent's
host pid. The NsSupervisor already watches every namespace member (§3.4), so this is
immediate — faster than the child could observe its own `ppid` change.

**Step 2 — identify orphaned children.** The NsSupervisor scans the shared member table
for live members whose `parent_host_pid` matches the dead parent's host pid. (Alternative:
walk the host ppid tree via `proc_pidinfo` for the dead parent's children. The shared
table scan is preferred — O(n) over allocated slots, no syscall overhead, no race with
launchd's reparenting.)

**Step 3 — set orphan flags.** For each orphaned child:

```rust
members[child_slot].flags.store(MEMBER_ORPHANED, Ordering::Release);
```

This is a single atomic byte write, visible to the child on its next `getppid` dispatch.

**Step 4 — guest `getppid` reads the flag.** The guest child's `getppid` dispatcher
(`creds.rs:530`) gains a check before the host-ppid translation:

```
if members[self_slot].flags.load(Acquire) == MEMBER_ORPHANED {
    return 1;    // ns-pid 1: the ns-init, per pid_namespaces(7)
}
// else: translate host ppid through the ns table as usual
```

This matches Linux's documented behavior (`pid_namespaces(7)`): "if the parent of a
process in a PID namespace terminates, the child is reparented to the init process of
the PID namespace (pid 1 within the namespace)." The orphan flag makes the reparenting
*appear* instantaneous from the child's perspective — the next `getppid` after the parent
dies returns 1, even though the macOS kernel reparented the host process to launchd.

**Step 5 — ns-init reaps orphans via `wait4(-1)`.** The ns-init's `wait4(-1, ...)` handler
(the emulated path in `proc.rs`) does two things:

1. **Host `waitpid(-1, WNOHANG)`** — reaps direct host children (processes the init
   actually forked). This covers the non-orphan case.
2. **Shared-memory scan** — iterates the member table looking for entries with
   `flags == MEMBER_DEAD` and `parent_host_pid` matching a dead member (i.e. orphans that
   died after being reparented). For each, it returns the orphan's ns-pid and the exit
   status harvested from `NOTE_EXITSTATUS` (stored in `members[slot].exit_status` by the
   NsSupervisor in step 1 of §3.4). The slot is then freed (`host_pid` zeroed).

**Step 6 — launchd reaps the host zombie.** The actual host-level zombie is reaped by
`launchd` (or collected by the NsSupervisor via `waitpid` if the NsSupervisor is the
process's host ancestor — it is, for init's direct children, but not for grandchildren
after reparenting). carrick's emulated `wait4` does not need to reap the host zombie; it
only reports the namespace-correct ns-pid and exit status. The host kernel handles the
real zombie lifecycle independently.

> **Note on `NOTE_EXITSTATUS`.** The kqueue `data` field for a `NOTE_EXIT` event on macOS
> carries the exit status in the same format as `waitpid`'s `status` out-parameter
> (observed). The NsSupervisor captures this at event-fire time and stores it in
> `members[slot].exit_status`, making it available for the ns-init's `wait4` scan even
> after launchd has reaped the host zombie (at which point `waitpid` from any other process
> would return `ECHILD`).

### 3.7 /proc visibility

The NsSupervisor is **not** a guest process. It runs no guest code, has no vCPU, and
executes no Linux syscalls. It is automatically invisible in `/proc` because
`is_guest_process` (`host_proc.rs:227`) validates a pid by walking its host ppid chain
**child→parent**, checking whether the chain reaches `ROOT_GUEST_PID`:

```rust
// host_proc.rs:227
pub fn is_guest_process(pid: u32) -> bool {
    // ...
    let root = ROOT_GUEST_PID.load(Relaxed);
    // walk ppid chain: cur → parent → grandparent → ...
    // return true iff we reach `root` or `me`
}
```

The NsSupervisor is **above** `ROOT_GUEST_PID` in the host tree (it is the root guest's
parent), so no guest's ppid chain ever passes through it — the chain goes
`guest-child → guest-init (== ROOT_GUEST_PID)` and stops. The NsSupervisor's own pid is
never tested because no guest process has it as an ancestor *below* the root.

**`ROOT_GUEST_PID` must be set to the guest-init's pid** (the child of the NsSupervisor
fork), not the NsSupervisor's pid. This happens naturally: `set_root_guest_pid(std::process::id())`
(`runtime.rs:1937`) is called in the **child branch** of the fork, where
`std::process::id()` returns the child's (guest-init's) host pid. The NsSupervisor
(parent branch) never calls `set_root_guest_pid` — it diverges into the kqueue loop
immediately after the fork.

This means no code change is needed in `host_proc.rs` to hide the NsSupervisor from
`/proc`. The existing ppid-walk logic, which has been the guest-visibility substrate since
before namespaces, handles it correctly by construction.

---

## 4. UID/GID namespace design

### 4.1 The Linux model (man-page summary)

From `user_namespaces(7)`:

- A user namespace owns a mapping from in-ns ids to parent-ns ids, defined by writing
  `/proc/[pid]/uid_map` and `/proc/[pid]/gid_map`. Each map line is
  `ID-inside-ns  ID-outside-ns  length` (three unsigned ints). At most **5 lines** per
  map (documented limit), and each map is **write-once** (a second write fails `EPERM`).
- An unmapped id appears as the overflow id **65534** (`nobody`/`nogroup`) — observed and
  documented.
- The **setgroups gate**: an unprivileged process must write `"deny"` to
  `/proc/[pid]/setgroups` *before* it may write `gid_map` (otherwise the `gid_map` write
  fails `EPERM`). Once `gid_map` is written, `setgroups` becomes read-only `"deny"`.
  Writing the maps requires `CAP_SETUID`/`CAP_SETGID` in the *parent* ns over the mapped
  range — but the creator of a new userns gets a full capability set in that ns, so the
  *self*-map case (writing your own child's map) is the common one.
- A newly created user namespace starts with the creating process having a **full set of
  capabilities** *within that namespace* (documented). Those caps are scoped to the ns:
  they grant power over resources owned by the ns, not the host.
- `getuid()` etc. return the **in-namespace** id (the id as mapped). Before any map is
  written, every id is the overflow id.

### 4.2 carrick model: a per-process `UserNs` handle + mapping table

Introduce a `UserNs` value object (lives in a new `crates/carrick-runtime/src/namespace/
user.rs`):

```text
struct IdMapEntry { inside: u32, outside: u32, length: u32 }   // a uid_map/gid_map line
struct UserNs {
    id: NsId,                       // stable identity (for ns/ symlink + setns)
    parent: Option<NsId>,           // nesting
    uid_map: OnceCell<Vec<IdMapEntry>>,   // write-once (<=5 entries)
    gid_map: OnceCell<Vec<IdMapEntry>>,   // write-once
    setgroups_allowed: AtomicBool,  // starts true; "deny" before gid_map if unprivileged
    setgroups_locked: AtomicBool,   // becomes true once gid_map written
}
```

Each guest process holds a `current_userns: NsId`. The **initial** userns is the identity
map (`0 0 4294967295` for both uid and gid, `setgroups=allow`) — matching observed default
Docker and carrick's current "guest is root" behavior, so the common case is unchanged.

**Translation functions** (the heart of the feature):

- `map_inside_to_outside(ns, id)` and `map_outside_to_inside(ns, id)` — walk the entries,
  return the overflow id `65534` (documented) when unmapped.
- `getuid/geteuid/getgid/getegid/getresuid/getresgid/getgroups` report the **in-ns** id.
  Concretely: carrick keeps `CredState` storing ids *as the guest sees them* (in-ns), and
  the userns map is consulted only at the ns boundary — e.g. when reporting `uid_map`,
  when a host operation needs the outside id, and when a child created in a *child* userns
  inherits creds (the parent's outside id becomes the child's overflow-or-mapped inside
  id). Because the default ns is identity, today's behavior (`CredState` ids == reported
  ids) is the identity special case and needs no change.
- `setuid/setresuid/...` keep the existing transition rules, but `is_privileged()` becomes
  "holds CAP_SETUID in `current_userns`" (≡ created/owns the ns, or euid 0 in the initial
  ns) rather than strictly `euid == 0`. This lets an unprivileged process that created a
  userns drop/raise ids *within its mapped range* the way Linux allows.

### 4.3 Writing the maps: `/proc/[pid]/uid_map`, `gid_map`, `setgroups`

These become **writable** synthetic files in `vfs/proc.rs`. Today the proc VFS is
read-only for these paths; we add a write path for exactly `self/uid_map`,
`self/gid_map`, `self/setgroups` (and the `[pid]/` equivalents for `pid ==` the writer,
which is the only case that matters since writing another live process's map needs a
parent relationship we model via the host tree).

Write rules to enforce (man-page-derived):

1. **uid_map / gid_map**: parse ≤5 whitespace-separated `inside outside length` triples;
   reject (`EINVAL`) malformed input, `>5` entries, overlapping ranges, or `length == 0`.
   `OnceCell` semantics: a second write → `EPERM` (write-once).
2. **Privilege**: if the writer is "privileged in the parent ns" (initial-ns euid 0, or
   creator of this ns mapping only ids it owns) → allow arbitrary ranges. Otherwise an
   unprivileged self-map may map only the single id `outside == euid` (uid_map) — the
   documented "unprivileged single-id" rule.
3. **setgroups gate**: writing `gid_map` while `setgroups_allowed && !privileged` → fail
   `EPERM`. The guest must write `"deny"` to `setgroups` first. After `gid_map` is
   written, `setgroups_locked = true` and `setgroups` reads `"deny"` and is read-only.
4. Writing `setgroups` `"allow"`/`"deny"` flips `setgroups_allowed` (only while unlocked).

**Reading**: `uid_map`/`gid_map` render the entries (or the identity line for the initial
ns); `setgroups` renders `allow`/`deny`. These satisfy the common probes (`cat
/proc/self/uid_map`) and tools that introspect their own map.

### 4.4 Capabilities

carrick has no real capability enforcement; it *models* CAP_SETUID/SETGID as euid 0
(`creds.rs:63`). The minimum to keep `apt`/`dpkg`/container inits happy:

- Report a **non-trivial CapEff/CapBnd/CapPrm** in `/proc/self/status` matching the
  observed Docker default `00000000a80425fb` for the initial (Docker) ns. (Today carrick
  prints `0`, which makes capability-probing tools think they have *nothing* and refuse to
  proceed; the observed Docker value is the right default.) For a process that created a
  fresh userns, report a **full** set (`0000003fffffffff`-class all-ones over the known
  cap range) within that ns — the documented "creator gets full caps in the new ns".
- `capget(2)`/`capset(2)` should be added as accept-and-record:
  `capget` returns the modeled set for `current_userns`; `capset` is accepted (recorded,
  not enforced) so libcap-based tools (`dpkg`, `setpriv`) don't abort. `prctl(PR_CAPBSET_*)`
  similarly accept/record.
- Keep `is_privileged()` driven by ns membership: in a fresh userns the creator is
  privileged for ns-local operations regardless of its host euid.

This is "fake but consistent": enough for tools that *query* capabilities to see a
coherent story, since carrick is the kernel and isn't actually enforcing DAC the way Linux
caps modulate it.

### 4.5 Fork-coherence

A userns is **shared among all its members** and survives fork. carrick forks real macOS
processes, so an in-memory `HashMap<NsId, UserNs>` in one process is invisible to a forked
sibling (per `[[feedback_durable_macos_gap_fills]]`). Storage options, in order of
preference:

- **Preferred: a durable file-backed registry** under a per-run scratch dir, e.g.
  `/tmp/carrick-ns-<root_guest_pid>/user/<ns_id>` containing the serialized maps +
  setgroups state, mirroring the existing `cred_ipc.rs` pattern
  (`/tmp/carrick-cred-<host_pid>`). Write-once is enforced by `O_CREAT|O_EXCL` /
  presence-of-file. `<ns_id>` is allocated from a monotonic counter file in the same dir.
  This is fork-coherent for free (the file exists for every descendant) and lifecycle-
  correct (cleaned up when the run ends, like `cred_ipc`).
- The map is **immutable after the one write**, which makes the file-backed approach
  trivial: write the file once, everyone reads it. The only mutable bit is the
  pre-`gid_map` setgroups flag, which lives only on the *writing* process before it writes
  the map (a child created after the map is finalized inherits the finalized state).
- `current_userns` per process can stay in `CredState`-adjacent in-memory state (it is a
  per-process attribute inherited at fork, exactly like creds), pointing at an `<ns_id>`.

### 4.6 Syscall touch-points (userns)

| Syscall / path | Change |
|---|---|
| `getuid/geteuid/getgid/getegid/getresuid/getresgid/getgroups` (creds.rs) | report in-ns ids (identity-ns: unchanged) |
| `setuid/setresuid/setreuid/setgid/...` (creds.rs) | `is_privileged()` becomes ns-capability-aware |
| `clone`/`clone3` w/ `CLONE_NEWUSER` (proc.rs) | allocate a child `UserNs` (initially empty maps), set child's `current_userns`, grant full caps in it |
| `unshare(CLONE_NEWUSER)` (NEW handler, nr 97) | allocate a new userns for the *caller*, full caps in it |
| `setns(fd, CLONE_NEWUSER)` (NEW handler, nr 268) | switch `current_userns` to the fd's ns (§6.6) |
| `/proc/self/uid_map`,`gid_map`,`setgroups` (vfs/proc.rs) | readable + writable (§4.3) |
| `/proc/self/status` `Uid:`/`Gid:`/`Cap*:`/`Groups:` (vfs/proc.rs) | render in-ns ids + modeled caps |
| `capget/capset`, `prctl(PR_CAPBSET_*)` | accept/record (§4.4) |

---

## 5. PID namespace design

### 5.1 The Linux model (man-page summary)

From `pid_namespaces(7)` / `clone(2)`:

- `CLONE_NEWPID` makes the *first child* created with that flag the **init (pid 1)** of a
  new pid namespace. The namespace is created at clone time; the *cloner* stays in its own
  ns and sees the child by its (parent-ns) pid; the *child* sees itself as pid 1.
- Processes see **ns-local pids**: `getpid()` returns the pid in the *innermost* ns the
  process is a member of. A process is simultaneously a member of every ancestor ns and
  has a (different) pid in each. The host/parent-ns pid differs from the ns-local pid.
- **pid 1 is special**: it reaps orphaned descendants (when a child's parent dies, the
  child is reparented to ns-pid-1, not host init); signals sent to it from within the ns
  are dropped unless it installed a handler (it has no default actions for most signals);
  and **when pid 1 of a ns exits, all other processes in the ns are killed with SIGKILL
  and the ns is torn down** (documented).
- `/proc` mounted inside the ns shows **only** ns members, with their ns-local pids.
- `getppid()` returns 0 for pid 1 (it has no parent *within the ns*), and for others the
  parent's ns-local pid (0 if the parent is outside the ns — observed).

### 5.2 carrick model: a host-pid ↔ ns-pid translation table + allocator

This is the central new structure. Today guest pid == host pid; we interpose a
**`PidNs`** with two maps and an allocator:

```text
struct PidNs {
    id: NsId,
    parent: Option<NsId>,
    level: u32,                          // 0 = root/initial ns
    next_pid: shared monotonic counter,  // hands out 1, 2, 3, ... (pid 1 first)
    // The bidirectional translation, shared across the whole process tree:
    host_to_ns: map<host_pid, ns_pid>,
    ns_to_host: map<ns_pid, host_pid>,
    init_host_pid: host_pid,             // who is pid 1 (set when the ns is created)
}
```

A process is a member of a *chain* of PidNs (its own innermost, then ancestors). It stores
`current_pidns: NsId` (per-process, inherited at fork). The **initial** PidNs (level 0) is
the identity map: `ns_pid == host_pid` for the root guest and its non-NEWPID descendants —
so single-process `run-elf` and non-namespaced multi-process runs are **unchanged**.

**carrick-side launch placement (the load-bearing path, per §1.0).** The primary way a
container enters a pid ns is NOT a guest syscall — it is carrick's `run` frontend acting as
runc. When `carrick run <image>` starts the root guest, the runtime creates a fresh `PidNs`
(level 1, `init_host_pid =` the root guest's host pid) and sets the root guest's
`current_pidns` to it *before the guest executes a single instruction*. The guest's very
first `getpid()` then returns 1, `/proc` is ns-filtered, etc. — with the guest having
issued no `clone(CLONE_NEWPID)`/`unshare` at all. The same applies to a fresh identity
`UserNs` (uid 0 inside). This launch-time setup is a small addition to the existing
`runtime.rs:1937` / `vfs/proc.rs:964` `set_root_guest_pid` bootstrap and is what makes
"run a container in a uid+pid namespace" work; the guest-syscall paths below are how a
guest that *itself* creates further namespaces is handled (the long-haul case).

**Allocator.** When a process is created (`fork`/`clone`) into a PidNs:
- Determine its host pid (the real macOS pid the runtime forked).
- For each ns in its chain (innermost-first), if not already mapped, allocate the next
  ns-local pid from that ns's `next_pid` and record both directions. The *first* process
  created with `CLONE_NEWPID` gets `ns_pid = 1` in the new ns (the allocator starts at 1).
- A non-NEWPID child created in an existing ns gets the next free ns-pid (2, 3, …).

**Translation functions** consulted by every pid-bearing syscall:
- `host_to_ns(ns, host_pid)` → the pid as the *caller's* ns sees it (or 0 if the target is
  outside the caller's ns subtree — observed for `getppid` of init).
- `ns_to_host(ns, ns_pid)` → the host pid to actually operate on (or `ESRCH` if the
  ns-pid names nothing in this ns).

### 5.3 Syscall touch-points (pid-ns)

| Syscall / path | Change |
|---|---|
| `getpid` (creds.rs:167) | return `host_to_ns(current_pidns, std::process::id())` — pid 1 for the init |
| `getppid` (creds.rs:530) | translate host ppid into `current_pidns`; pid 1 → 0; reparented orphans → 1 |
| `gettid` (proc.rs:589) | single-threaded → ns getpid; threads keep per-process tids (tids are not ns-translated across processes — a thread tid is only meaningful in its own process, and carrick's `ThreadRegistry` is per-process) |
| `clone`/`fork` return value (runtime.rs:657) | parent must receive the **child's ns-pid**, not its host pid; allocate the mapping *before* returning, then translate |
| `wait4` (proc.rs:1302) | translate the `pid` arg ns→host before `libc::wait4`; translate the **returned reaped pid** host→ns before handing it back; `pid == -1`/`0` (any child / pgrp) wait stays host-level but the *result* is ns-translated |
| `waitid` (proc.rs:1180) | same translation as wait4 for `P_PID`/the returned `si_pid` |
| `kill`/`tgkill`/`tkill` (signal.rs) | translate `pid` arg ns→host before `libc::kill`; reject ns-pids that aren't members (`ESRCH`); `kill(1, ...)` from inside hits the ns init |
| `/proc` enumeration (vfs/proc.rs:243) | list ns members by their **ns-local** pids; map each `/proc/<ns_pid>` to its host pid for `pid_info` |
| `/proc/self/status` `Pid:`/`PPid:`/`NSpid:` (vfs/proc.rs:635) | `Pid` = ns getpid; add `NSpid:` line listing the pid in each ns of the chain (innermost-first), matching observed Docker `NSpid:` |
| `pidfd_open`/`CLONE_PIDFD` (proc.rs:288) | pidfd already keys on host pid internally; only the *guest-visible* pid arg/return needs translation |
| `setns`/`unshare(CLONE_NEWPID)` | §5.5 / §6.6 |

The mapping must be **allocated in the runtime fork path** (`runtime.rs:657
DispatchOutcome::Fork`), because that is where the host child pid first becomes known. The
parent branch (`ForkOutcome::Parent { child_pid }`) currently returns `child_pid`
(host pid) directly as the clone return — this becomes
`host_to_ns(current_pidns, child_pid)` after registering the new mapping. The child branch
(`ForkOutcome::Child`) updates its `current_pidns` (a new ns if `CLONE_NEWPID` was set,
else inherited).

### 5.4 init (pid 1) semantics

- **Reaping orphans.** Linux reparents an orphan to ns-pid-1. Since macOS lacks a subreaper primitive and reparents orphans to launchd, carrick solves this using the NsSupervisor's orphan-flag protocol (§3.6). 
  1. The NsSupervisor detects the death of a parent process via `EVFILT_PROC`/`NOTE_EXIT` (§3.4) and flags surviving children as `MEMBER_ORPHANED` in the `MAP_SHARED` region.
  2. The guest child's `getppid()` dispatcher checks this flag and returns `1` (ns-pid 1, the ns-init) rather than translating the real host ppid (which now points to launchd).
  3. When an orphaned process eventually exits, the NsSupervisor captures its exit status from `NOTE_EXITSTATUS` and stores it in the `MAP_SHARED` region.
  4. The ns-init's `wait4(-1, ...)` handler (`proc.rs:1302`) reaps direct host children using `waitpid(-1, WNOHANG)` and reaps orphaned grandchildren by scanning the shared "dead orphans" table. This ensures the guest init receives the correct child pid and status. The underlying host zombie is cleaned up by launchd.
- **Signal defaults for pid 1.** Within the ns, signals without an installed handler are dropped for pid 1 (it can't be killed by its own children's default SIGTERM). Model this in `signal.rs`: when the *target* resolves (via translation) to the ns init and the sender is in the same ns and the init has no handler for that signal, drop it (return success, deliver nothing) — except SIGKILL/SIGSTOP from an *ancestor* ns (host side), which still work because they go through the real host kill.
- **pid-1 exit tears down the ns.** When the process that is ns-pid-1 exits, the NsSupervisor detects its termination via `waitpid` (since the guest-init is the NsSupervisor's direct child). The NsSupervisor then performs atomic namespace teardown:
  1. It issues `killpg(ns_pgid, SIGKILL)` as a fast atomic path to target the namespace process group.
  2. It iterates through the shared `MAP_SHARED` member slots and issues `kill(host_pid, SIGKILL)` to any escapees that left the main group using `setpgid`/`setsid` to ensure no member survives teardown.
  3. It cleans up the namespace files and shared-memory entries, and exits, propagating the guest-init's exit status.

### 5.5 unshare(CLONE_NEWPID) subtlety

`unshare(CLONE_NEWPID)` does **not** move the caller into the new ns; it makes the
**caller's next child** the init of the new pid ns (documented — distinct from
`CLONE_NEWUSER` which moves the caller). So `unshare(CLONE_NEWPID)` sets a *pending*
"next fork creates a NEWPID ns" flag on the caller; the subsequent `fork` consumes it. This
must be modeled as a per-process pending flag, checked in the fork path.

### 5.6 Fork-coherence of the translation table

The pid translation table is shared by the entire guest process tree and mutated on every fork (a new mapping entry). In accordance with the NsSupervisor architecture, the translation table is backed by a two-tier storage model:

1. **Hot mutable state** (monotonic PID allocator counter, member slots, orphan flags, dead member exit statuses) is housed in the `MAP_SHARED|MAP_ANON` region (§3.3) allocated by the root carrick process before the first fork. 
   - Allocation is lock-free, crash-safe, and O(1) using hardware-atomic `AtomicU32::fetch_add` on the shared page. Siblings forking concurrently each obtain a guaranteed unique ns-pid from the hardware exclusive-monitor without locks, file contention, or retry loops.
   - The shared table maintains a fixed array of slots (e.g. 1024 slots) containing atomic host pids, ns-local pids, parent host pids, liveness/orphan flags, and exit statuses.
2. **Cold write-once state** (`uid_map`/`gid_map` configurations and `ns_pid -> host_pid` numbering records) is written as durable `O_CREAT|O_EXCL` files under `/tmp/carrick-ns-<root>/`. The file-creation atomicity guarantees single-winner publication. These files serve as the durable recovery record and facilitate filesystem-based inspection for debuggability (e.g. `ls /tmp/carrick-ns-*/pid/`).
3. **Membership and Liveness** are derived dynamically from the host process tree via the `is_guest_process` ppid-chain walk (`host_proc.rs:227`), avoiding the need for an active membership database in memory.

### 5.7 Worked example: `CLONE_NEWUSER | CLONE_NEWPID` (Docker combo)

`runc` typically does both. Order that matters (man-page-derived):

1. The user namespace is created first (or simultaneously); the new userns gives the
   creator full caps, which is what *authorizes* creating the pid ns and writing the maps.
2. The maps (`uid_map`/`gid_map`, with the setgroups-deny gate if unprivileged) are written
   by the **parent** into the child's `/proc/[pid]/uid_map` *before* the child does
   anything that depends on its identity.
3. The child becomes pid 1 of the new pid ns and execs the container entrypoint.

In carrick: a single `clone(CLONE_NEWUSER|CLONE_NEWPID|SIGCHLD, ...)` (or the unshare
sequence) allocates *both* a `UserNs` (full caps, empty maps) and arms a pending-NEWPID;
the forked child gets `current_userns = new`, becomes `ns_pid = 1` in the new `PidNs`. The
parent then writes the child's `uid_map`/`gid_map` via `/proc/<child_ns_pid>/uid_map`
(translated to the child's host pid for the actual store write). Because the default Docker
case is *identity userns + fresh pidns*, the high-value Phase ordering is: **pid ns first**
(it is what's actually different from carrick today), userns map-files second.

---

## 6. macOS-host impedance mismatches

### 6.1 One host process per guest process; no real Linux namespaces on macOS

macOS has no namespaces. Every namespace effect is *synthesized* by carrick's dispatcher
and `/proc` VFS. The leverage point is that carrick is already the kernel for these
syscalls — `getpid`, `wait4`, `kill`, `/proc` all flow through code we own. We are not
fighting the host; we are choosing what number to report. The host kernel remains the
source of truth for **liveness, parentage, and resource state** (`host_proc.rs`), and we
layer a *numbering + filtering* translation on top.

Apple's own answer to Linux-container workloads on macOS is full-VM isolation: the
**Containerization framework** (announced WWDC 2025) builds OCI-compatible containers on
top of `Virtualization.framework`, booting a minimal Linux kernel per container rather
than adding namespace primitives to XNU. XNU has no plans for kernel-level namespaces —
the Darwin process model has no `struct nsproxy`, no `/proc/[pid]/ns/`, and no
`CLONE_NEW*`-style flags. This is a deliberate architectural position (macOS isolation is
SIP + sandbox profiles + entitlements + TCC, not identity-virtualizing namespaces) and
validates carrick's userspace-emulation approach: there is nothing to adopt; the
dispatcher and `/proc` VFS *are* the namespace kernel.

### 6.2 The pid-translation seam is small and already half-built

`host_proc::is_guest_process` (ppid-walk) + `enumerate_guest_pids` + `pid_info` already
give "who are my guest processes and what's their state". A PID namespace adds (a) a stable
ns-pid *number* per host pid and (b) a *filter* (only members of the caller's ns). Both
plug into the existing functions: `enumerate_guest_pids` gains a "restrict to ns members
and relabel to ns-pids" variant; `pid_info(host_pid)` is reused unchanged after ns→host
translation.

### 6.3 Fork-coherence: the resolved constraint

The decisive constraint: namespace tables are *shared and survive fork*, so they must NOT
be plain in-process `HashMap`s. carrick forks real macOS processes; an in-memory map in
one process is invisible to a forked sibling.

**Resolution: two-tier storage.**

1. **Hot mutable state** — the PID allocator counter (`AtomicU32`), orphan-reparented
   flags, and member-liveness bits — lives in a **`MAP_SHARED|MAP_ANON` region** allocated
   before the first guest fork. This is the same pattern already proven in
   `guest_cpu.rs:112–133` (`init_child_table`), where a shared anonymous mapping holds an
   array of `ChildSlot` structs accessed through `AtomicU64` fields across forked
   processes. The namespace allocator extends this: a single shared page holds the
   monotonic `next_pid: AtomicU32`, per-namespace orphan flags, and a small liveness
   bitmap.

   `AtomicU32::fetch_add` is **hardware-atomic across processes** on Apple Silicon: the
   underlying `LDAXR`/`STXR` (load-acquire-exclusive / store-exclusive) pair operates on
   the **physical page** backing the shared mapping, so two processes racing
   `fetch_add` on the same `AtomicU32` in a `MAP_SHARED` page get exactly the
   cross-process atomicity the allocator needs — lock-free, crash-safe, O(1). macOS
   `MAP_SHARED|MAP_ANON` sets `VM_INHERIT_SHARE` automatically (observed; the Mach VM
   inheritance mode for shared anonymous regions), so every `fork` descendant maps the
   identical physical pages without any explicit inheritance setup.

   > **This is the primary resolution of Risk #1** from §8 ("fork-coherence of the
   > pid-translation table is the make-or-break"). Two siblings forking concurrently
   > each `fetch_add` the shared counter and receive distinct ns-pids, without locks,
   > files, or retry loops.

2. **Cold write-once state** — `uid_map`/`gid_map` entries and `ns_pid→host_pid` mapping
   records — lives in **`O_CREAT|O_EXCL` files** under
   `/tmp/carrick-ns-<root_guest_pid>/`, extending the `cred_ipc.rs` pattern
   (`cred_ipc.rs:47–58`). Each file is created atomically (the kernel guarantees
   `O_EXCL` races produce exactly one winner); each is written once and read many times.
   `uid_map` entries are immutable after the one write (§4.3); `ns_pid→host_pid` records
   are immutable by construction (a pid is assigned once and never reassigned in a
   monotonic allocator). This makes the file-backed approach trivial: write once, everyone
   reads, no coordination.

3. **Membership and liveness** are derived from the host process tree — `host_proc.rs`'s
   `is_guest_process` ppid-walk and `pid_info` — which is already fork-coherent (the host
   kernel is the substrate, not carrick memory). Membership of a PID namespace =
   "host pids whose ppid-chain reaches the ns init's host pid without crossing another
   `CLONE_NEWPID` boundary" (§4.6). No shared data structure is needed for this; it is
   computed on demand from the authoritative host tree.

### 6.4 macOS primitives leveraged

The following Darwin/XNU/macOS primitives are used or planned for use in the namespace
implementation. Each is already exercised in carrick production code unless marked
*"extend"*.

| # | Primitive | Namespace role | Properties | carrick code reference |
|---|-----------|---------------|------------|----------------------|
| 1 | **`AtomicU32` in `MAP_SHARED\|MAP_ANON`** | PID allocator (`next_pid` counter) | Lock-free, crash-safe, O(1). `LDAXR`/`STXR` on Apple Silicon operates on physical addresses; hardware-atomic across processes sharing the page. No recovery protocol needed — a process that dies mid-`fetch_add` simply got a pid it never used; the counter is still monotonic. | *Extend* from `guest_cpu.rs:112–133` (`init_child_table`: `MAP_SHARED\|MAP_ANON` + `AtomicU64` slot array, called before first fork, inherited by all descendants). |
| 2 | **`EVFILT_PROC` / `NOTE_EXIT`** (kqueue) | Namespace member lifecycle tracking | One-shot process-exit notification. Does NOT consume the child's exit status (safe to pair with `wait4`). Fires even if the watcher is not the parent. | `darwin_kqueue.rs:119–137` (`Kevent::proc_exit`); `host_signal.rs:200–228` (`register_child_exit_watch`, arming watches on the signal pump's kqueue for every forked guest child). Extend: the `NsSupervisor` registers `NOTE_EXIT` on every namespace member from its own kqueue, detecting member death for orphan-reparent and ns-teardown-on-init-exit. |
| 3 | **Process groups (`setpgid` / `killpg`)** | Atomic namespace teardown (optimization) | `killpg(pgid, SIGKILL)` is a single kernel syscall that atomically iterates all group members — the XNU `pgsignal` path walks the `pgrp` list under a lock. Used as the *fast path* for pid-ns teardown when init exits: if all ns members share a process group (common for a container launched as one pgid), a single `killpg` replaces iterating the member list. Falls back to per-member `kill(host_pid, SIGKILL)` when pgids diverge. | No current carrick use of `killpg`; `signal.rs` passes guest `kill(-pgid, sig)` through to host `libc::kill` which handles negative-pid as pgid. *New*: teardown path adds explicit `killpg`. |
| 4 | **`proc_pidinfo` / `PROC_PIDTBSDINFO`** | Process tree introspection; namespace membership derivation | Returns ppid, pgid, uid, gid, state, comm for any inspectable pid. The substrate for `is_guest_process` (ppid-chain walk) and `pid_info`. No privilege required for same-uid processes. | `host_proc.rs:88–104` (`bsdinfo`); `host_proc.rs:209–219` (`pid_info`); `host_proc.rs:227–251` (`is_guest_process`, 256-step bounded ppid walk). The namespace membership query ("is this pid in my ns?") is a refinement of the existing `is_guest_process` walk: same walk, additional boundary check at `CLONE_NEWPID` init pids. |
| 5 | **`mmap(MAP_SHARED\|MAP_ANON)`** | Shared memory regions (guest RAM, namespace tables) | `VM_INHERIT_SHARE` automatic on macOS for `MAP_SHARED`; region survives fork with identical physical backing. Zero-initialized by the kernel. | `shared_aperture.rs:1–8` (the entire shared-file aperture: one `MAP_ANON\|MAP_SHARED\|MAP_NORESERVE` region `hv_vm_map`'d at boot); `guest_cpu.rs:119–128` (child CPU accounting table); `memory.rs:206` (guest `MAP_SHARED\|MAP_ANON` routing). *Extend*: a new shared page for namespace hot state. |
| 6 | **`O_CREAT\|O_EXCL`** | Atomic write-once file creation (namespace data files) | Kernel-guaranteed single-winner race resolution. The file either didn't exist (creator wins, gets the fd) or did (loser gets `EEXIST`). Combined with `rename` for atomic-content publication. | `cred_ipc.rs:47–58` (per-process credential publication: `O_NOFOLLOW` + `write` + `rename`); guest `open()` path (`fs.rs:360`, `fs_backend.rs:1752`). *Extend*: `/tmp/carrick-ns-<root>/pid/<ns_id>/<ns_pid>` files created `O_EXCL`, containing the host_pid — the write-once numbering record. |

### 6.5 macOS primitives investigated and ruled out

The following primitives were researched as potential namespace-implementation building
blocks and found unsuitable. Each entry documents the specific macOS behavior that
disqualifies it; these are observed behaviors and Apple documentation findings, not Linux
kernel source.

| # | Primitive | Why investigated | Why ruled out |
|---|-----------|-----------------|---------------|
| 1 | **`os_unfair_lock` in shared memory** | Fast userspace mutex; potential cross-process lock for the PID allocator. | Apple documentation (`os/lock.h`, WWDC sessions) explicitly states `os_unfair_lock` is **not safe for cross-process use**. The implementation encodes the owning thread's identity (mach port + process) in the lock word; a different process's thread attempting to acquire sees a corrupted owner. The `AtomicU32::fetch_add` approach (§6.3) eliminates the need for a cross-process lock entirely. |
| 2 | **`pthread_mutex_t` with `PTHREAD_PROCESS_SHARED`** | POSIX-standard cross-process mutex; the textbook approach for shared-memory coordination. | macOS **does not implement `PTHREAD_MUTEX_ROBUST`** (`pthread_mutexattr_setrobust` returns `EINVAL` or is absent — observed). If a process holding the lock is `SIGKILL`ed (e.g. OOM, or ns-teardown killing members), the lock is **permanently stuck**: every other process blocks forever in `pthread_mutex_lock`. Unacceptable for a PID allocator that must survive member crashes. Linux's robust-mutex protocol (the `robust_list` head, kernel-mediated `EOWNERDEAD`) has no macOS equivalent. |
| 3 | **`NOTE_TRACK`** (kqueue `EVFILT_PROC`) | Auto-follow forks: register once on a process and automatically receive events for all its descendants. Would simplify namespace membership tracking. | **Deprecated since macOS 10.5 (Leopard)**; returns `ENOTSUP` on modern macOS (observed). XNU's `filt_proc` explicitly rejects `NOTE_TRACK` with `EV_ERROR`. Must register `NOTE_EXIT` on each pid individually — which is what `host_signal.rs:200` already does. The per-member registration pattern scales adequately for container-sized process trees (tens to low hundreds of members). |
| 4 | **`PR_SET_CHILD_SUBREAPER`** | Linux `prctl` that makes a process the reap target for orphaned descendants (the mechanism pid-1-of-a-ns uses). A macOS equivalent would solve orphan reparenting. | **Does not exist on macOS.** XNU has no subreaper concept; orphans always reparent to `launchd` (host pid 1). No `proc_info` flag, no `sysctl`, no Mach equivalent. Resolved by the NsSupervisor's orphan-flag protocol: when a namespace member's parent dies, the `EVFILT_PROC`/`NOTE_EXIT` watch fires, the supervisor sets the orphan flag in shared memory, and the namespace init's `wait4` path reaps the orphan. |
| 5 | **XNU Personas (`kpersona_alloc`)** | Conceptually analogous to user namespaces: a "persona" is a virtualized uid/gid identity the kernel can assign to a process subtree. Could provide kernel-backed uid translation. | Gated by the **private Apple entitlement** `com.apple.private.persona-mgmt` (observed via `kpersona_alloc` returning `EPERM` without it). The entitlement is not available to third-party developers; the API is undocumented and unstable. Even if accessible, personas are a fixed-identity override, not a bidirectional mapping table — they could not express `uid_map`'s arbitrary range translations. |
| 6 | **Endpoint Security Framework (ESF)** | Real-time notification of process lifecycle events (exec, fork, exit) and syscall authorization. Could track namespace membership via OS-level hooks. | Requires an **Apple-granted entitlement** (`com.apple.developer.endpoint-security.client`), obtainable only through an approved provisioning profile. Carrick already intercepts every guest syscall at the HVF `hv_vcpu_run` trap boundary — ESF would be a redundant, lower-fidelity observation point (it sees host syscalls, not guest intent). The approval dependency makes it unsuitable for open-source distribution. |
| 7 | **macOS Sandbox profiles (SBPL)** | Could restrict a namespace member's access to host resources, providing mount-namespace-like isolation. | Sandbox profiles control **access, not identity**. They cannot remap uids/pids or synthesize a virtual `/proc`; they can only allow/deny operations on real host paths. The profile DSL (`(allow ...)` / `(deny ...)`) is undocumented and private — Apple ships no public specification and profiles break across OS versions. Carrick's VFS layer already mediates all file access; SBPL would add a second, less controllable access-control layer with no namespace benefit. |
| 8 | **POSIX shared memory (`shm_open`)** | Named shared memory; potential alternative to `MAP_SHARED\|MAP_ANON` for the namespace tables. | macOS imposes a **31-character name limit** (`PSHMNAMLEN`, observed; documented in `sys/posixshm.h`). `/dev/shm` does not exist on macOS — shared memory objects are kernel-only, invisible in the filesystem, and cannot be inspected for debugging. No crash-cleanup advantage over anonymous shared mappings (both leak if the process tree is `kill -9`'d without cleanup). `MAP_SHARED\|MAP_ANON` is simpler (no name to manage, no `shm_unlink` to forget) and already proven in `guest_cpu.rs`. Named files under `/tmp/carrick-ns-*` are better for the write-once data (inspectable, cleanable by path). |
| 9 | **Named POSIX semaphores (`sem_open`)** | Cross-process semaphore; potential synchronization primitive for the PID allocator or namespace lifecycle gates. | **Kernel-persistent until reboot** if not `sem_unlink`'d (observed). A carrick crash leaves orphaned semaphores in the kernel's POSIX semaphore table; there is no `ipcrm`-equivalent cleanup tool on macOS (SysV IPC has `ipcrm`; POSIX semaphores do not). A process killed while `sem_wait`'d leaves the semaphore decremented with no recovery (no robust-semaphore protocol). The lock-free `AtomicU32::fetch_add` approach needs no semaphore at all. |
| 10 | **`proc_listchildpids`** | Could enumerate a namespace init's direct children without a ppid-chain walk. | Returns **direct children only** — no recursive descent into grandchildren. A PID namespace's membership is the entire subtree, not just one level. Not better than the existing ppid-chain walk (`host_proc.rs:227–251`), which already handles arbitrary depth (bounded at 256 steps) and works for the "is this pid a member of ns rooted at init?" query. Adding `proc_listchildpids` would require recursive calls and still miss reparented orphans (whose parent is now `launchd`, not the ns init). |
| 11 | **`waitid(P_ALL)` / `waitid(P_PGID)`** | Reap orphaned grandchildren that were reparented to the namespace init. Could implement the pid-1 "reaps all orphans in the ns" semantic. | On macOS (and POSIX generally), `waitid` and `waitpid` can only wait for **direct children** of the calling process, not arbitrary descendants. Orphans reparented to `launchd` (host pid 1) are no longer the ns-init's children in the host's process table — `waitid(P_ALL)` in the ns init will never see them. The orphan-reaping protocol must use `EVFILT_PROC`/`NOTE_EXIT` (which works on any inspectable pid) combined with the shared-memory orphan flag, not `waitid`. |
| 12 | **POSIX.1e capabilities** | If macOS had capabilities, the user-namespace capability set could be backed by real kernel state rather than emulated in software. | **macOS has no capability system.** Privilege is binary (euid 0 vs non-zero), modulated by SIP (System Integrity Protection), TCC (Transparency, Consent, and Control), and per-binary entitlements — none of which map to Linux's fine-grained `CAP_*` model. There is no `capget`/`capset` equivalent, no `prctl(PR_CAPBSET_*)`, no ambient/inheritable/permitted/effective/bounding distinction. Linux capabilities must be emulated entirely in software (§3.4: modeled cap sets in `CredState`, reported through `/proc/self/status`, accepted-and-recorded by `capget`/`capset` stubs). |

### 6.6 Nested namespaces and `setns`

- **Nesting**: both `UserNs` and `PidNs` carry a `parent: Option<NsId>` and (for pid ns) a
  `level`. A process is a member of its chain; `getpid` reports the innermost; `NSpid:`
  lists the chain. Allocation walks the chain innermost-first. This is sufficient for the
  buildkit/nested-container cases; deep nesting is bounded by the host ppid-walk's 256-step
  cap already in `host_proc.rs:237`.
- **`setns(2)`**: needs ns *handles* — Linux exposes them as `/proc/[pid]/ns/{user,pid}`
  magic symlinks (e.g. `user:[4026531837]`). carrick currently has no `ns/` dir. Phase 4
  adds: synthetic `/proc/[pid]/ns/user` and `ns/pid` symlinks rendering `kind:[ns_id]`
  (the `NsId` doubles as the inode-like number); `open()` on them yields an fd carrying the
  `NsId`; `setns(fd, flag)` switches the caller's `current_userns`/`current_pidns` to that
  `NsId` (pid-ns `setns` only affects *future children*, per the man page, like
  unshare-newpid). This is the lowest-priority piece — most Docker images never call
  `setns` (that's the runtime's job, performed *outside* the container).

**Process-group and session ID handling across phases:**

- **Phase 2 (current architecture, pass-through):** `setpgid(2)` and `setsid(2)` pass
  through to the host kernel — the guest's pgid/sid are real host pgids/sids. This is
  correct because within a single PID namespace all processes share the same host pgid
  space, so host pgids are internally consistent. Guest `kill(-pgid, sig)` passes through
  to host `libc::kill` (negative pid = pgid semantics, man-page-documented); guest
  `waitpid(-pgid, ...)` passes through to host `libc::waitpid`. Namespace teardown
  (pid-1 exit) uses the membership list sweep (enumerate all ns members from the
  `host_to_ns` table and `kill(host_pid, SIGKILL)` each); `killpg` is an
  *optimization-only* fast path when all members happen to share a process group.

- **Phase 4 (full virtualization):** pgids and sids become ns-local pids — the same
  numbering space as process pids within the namespace (man-page-documented:
  `setpgid(7)` / `credentials(7)` — a process group ID is the PID of the group leader;
  a session ID is the PID of the session leader). The existing PID-namespace translation
  functions (`host_to_ns` / `ns_to_host`) handle them automatically with no separate
  pgid/sid translation table. `setpgid(ns_pid, ns_pgid)` translates both arguments to
  host pids before calling host `libc::setpgid`; `getpgid`/`getsid` return values are
  translated host→ns. `kill(-ns_pgid, sig)` translates `ns_pgid` to its host pgid, then
  calls `libc::kill(-host_pgid, sig)`. This works because the host kernel's process
  groups are a superset of the namespace's view — every ns member's host pgid is valid on
  the host — and the translation is a simple lookup, not a structural change.

---

## 7. Phased implementation plan

> **Implementation status (2026-05-31).** Phases 1–3 are **implemented and
> verified** against the Docker oracle (full conformance suite green): the
> userns map files + capability surface (Phase 1), launch-time pid-ns placement
> + host↔ns pid translation across every pid-bearing syscall (Phase 2a), the
> per-container NsSupervisor with orphan reparenting + teardown (Phase 2b/3),
> and pid-1 signal-default protection (Phase 3). Probes added: `usernsmap`,
> `usernswrite`, `pidnsroot`, `pidnswait`, `pidnsinitreap`, `pidnsinitsig`,
> `pidnsorphanreap`. Beyond the original plan, `carrick run` gained
> `--pid host|private` (docker parity), `-d` (detached, under a per-container
> supervisor), and the `ps`/`stop`/`kill`/`rm` lifecycle — all **daemonless**
> (per-container supervisor + on-disk registry, no `carrickd`). **Phase 4
> (guest-facing `setns`/`unshare(CLONE_NEWPID)` + `/proc/[pid]/ns/` symlinks)
> remains the open long-haul item.** `unshare(CLONE_NEWUSER)` and the
> `CLONE_NEW*` constants already exist.

Each phase lists critical files, the conformance probe(s) to add under
`conformance-probes/src/bin/` (run against Docker via the existing harness — see
`credtransition.rs` / `clone3args.rs` as templates), and a
Docker-oracle validation.

**Ordering reflects the §1.0 priority: "run a container placed in uid+pid namespaces"
first; "let a guest create its own namespaces" (full `unshare`/`setns`) last (long-haul).**
The critical-path phases (2 and 3) need NO guest namespace syscalls — carrick places the
root guest in the namespaces at launch and presents the correct view. Phase 1 is the cheap
userns-view prerequisite; Phase 4 is the optional guest-facing syscall layer.

### Phase 1 — userns map files + capability surface (satisfies `docker run` defaults)
Smallest, highest "looks like Docker" payoff; mostly `/proc` plumbing, little semantic risk
because the default map is identity (matches today's "guest is root").

- **Files:** `vfs/proc.rs` (add readable+writable `self/uid_map`, `gid_map`, `setgroups`;
  fix `/proc/self/status` `CapEff/CapBnd/CapPrm` to the observed Docker default
  `00000000a80425fb`, render `Uid:/Gid:` from `CredState`); a new `namespace/user.rs` for
  `UserNs` + the write-once parser/validator; `cred_ipc.rs`-style store under
  `/tmp/carrick-ns-<root>/user/`. `carrick-abi/src/lib.rs` (add `CLONE_NEW*` constants).
  *Capabilities integration:* Add `CapabilitySet` struct to `CredState` (in `creds.rs`)
  initialized to the Docker default; implement `capget`/`capset` and `prctl(PR_CAPBSET_*)`
  as software bookkeeping stubs so that libcap-based tools query a coherent state and
  don't abort.
- **Probe:** `usernsmap.rs` — read `/proc/self/uid_map` (assert identity line
  `0 0 4294967295`), read `/proc/self/setgroups` (assert `allow`), read `CapEff` from
  `/proc/self/status` (assert non-zero == the Docker default). All deterministic booleans.
- **Probe:** `usernswrite.rs` — `unshare(CLONE_NEWUSER)` (Phase 1 may stub unshare to just
  allocate the ns), write `"deny"` to setgroups then `gid_map`, assert second `uid_map`
  write → EPERM (write-once), assert gid_map-before-deny → EPERM (setgroups gate).
- **Docker oracle:** `docker run --rm debian:stable sh -c 'cat /proc/self/uid_map; cat
  /proc/self/setgroups; grep CapEff /proc/self/status'` vs the same under carrick — verdicts
  must MATCH.

### Phase 2 — NsSupervisor + pid-ns translation + launch-time placement + getpid/getppid/wait (the real gap, critical path)
The core value: a container launched by `carrick run` sees its init as pid 1, with **no
guest namespace syscall involved** — carrick places the root guest in a fresh pid ns at
launch (§5.2 "launch placement") and presents the translated view.

- **Files:**
  - `namespace/pid.rs` (`PidNs`, allocator, host↔ns translation, durable numbering store).
  - `runtime.rs` (in `run_threaded_hvf_loop`, allocate `MAP_SHARED|MAP_ANON` region before fork,
    execute the fork into NsSupervisor parent and guest-init child, run the supervisor's kqueue event loop).
  - `creds.rs` (`getpid`/`getppid` translate; `getppid` reads shared orphan flags to return 1 for orphans).
  - `proc.rs` (`wait4`/`waitid` translate arg + result).
  - `runtime.rs:657` fork path (child self-registers into `MAP_SHARED` region using monotonic atomic counter
    and `O_CREAT|O_EXCL` file, and sends a single wake-up byte on the registration pipe; parent returns translated ns-pid).
  - `signal.rs` (`kill`/`tgkill` translate arg).
  - `vfs/proc.rs` (`/proc/self/status` `Pid:`/`PPid:`/`NSpid:`; ns-filtered enumeration).
- **Primary probe (launch placement, no guest ns syscall):** `pidnsroot.rs` — run as the
  *root guest* under `carrick run`; assert `getpid()==1`, `getppid()==0`, `/proc/self/status`
  `Pid: 1`, and that a plain `fork` child gets a small ns-pid (2) and is reaped by ns-pid 1
  via `wait4`. This is the test that proves "the container is in a pid namespace".
- **Probe:** `pidnswait.rs` — root guest forks two children; assert `wait4(-1)` returns
  ns-local pids (2, 3) and `kill(child_ns_pid, 0)` succeeds while a foreign ns-pid → ESRCH.
- **Probe (long-haul, guest-created ns):** `pidnsclone.rs` — `clone(CLONE_NEWPID|SIGCHLD)`;
  child asserts `getpid()==1`/`getppid()==0`; parent asserts the clone return is the child's
  parent-ns-pid and `wait4` reaps it.
- **Docker oracle:** `docker run --rm debian:stable sh -c 'echo $$; grep -E "^(Pid|NSpid):"
  /proc/self/status'` (expect `1`) vs the same image under carrick — verdicts MATCH.

### Phase 3 — pid-1 init semantics (reaping, signal defaults, ns teardown)
- **Files:** `proc.rs` (`wait4(-1)` in init translates and reaps direct children plus orphans recorded in the shared
  dead-orphans table); `signal.rs` (drop unhandled signals to the ns init from within the ns; preserve
  ancestor-ns SIGKILL/SIGSTOP); `runtime.rs`/NsSupervisor teardown loop (detect guest-init exit, call `killpg(ns_pgid, SIGKILL)`
  fast path, then sweep members list to SIGKILL escapees).
- **Probe:** `pidnsinitreap.rs` — init forks a child that forks a grandchild then the child
  exits; assert the grandchild reparents to the init (its `getppid()==1` due to NsSupervisor orphan flag)
  and the init can `wait4` it. `pidnsinitsig.rs` — child sends default SIGTERM to pid 1 (no
  handler) → init survives; init with a handler receives it.
- **Probe:** `pidnsteardown.rs` — init exits while a child runs; assert the child is killed
  (observe via the parent-ns wait status SIGKILL).
- **Docker oracle:** reproduce reparent-to-1 and "kill -TERM 1 with no handler is ignored"
  in `docker run` and diff.

### Phase 4 — setns/unshare + ns/ symlinks (LONG-HAUL: guest-created namespaces)
- **Files:** `dispatch/mod.rs` (wire nr 97 `unshare`, nr 268 `setns`); `proc.rs`/`creds.rs`
  (unshare-NEWUSER moves caller; unshare-NEWPID arms pending-next-child; setns switches
  current ns); `vfs/proc.rs` (`/proc/[pid]/ns/{user,pid}` magic symlinks + open→ns-fd);
  `namespace/*` (resolve an fd to its `NsId`). Accept-and-ignore `CLONE_NEWNS/UTS/IPC/
  CGROUP`; reject/ignore `CLONE_NEWNET` (out of scope).
- **Probe:** `unsharenewuser.rs` — `unshare(CLONE_NEWUSER)`; assert `geteuid()` reflects the
  pre-map overflow then the mapped id after writing uid_map; `readlink(/proc/self/ns/user)`
  changes vs the initial ns. `setnsuser.rs` — open a peer's `ns/user`, `setns`, assert
  membership.
- **Docker oracle:** `docker run --rm debian:stable unshare -Ur cat /proc/self/uid_map` (a
  rootless self-map) vs carrick.

---

## 8. Top risks and open questions

### Risks

1. **Fork-coherence of the pid-translation table.**
   > [!NOTE]
   > **RESOLVED**
   > Hardware atomics (`AtomicU32::fetch_add`) in a `MAP_SHARED|MAP_ANON` region allocated prior to the first guest fork provide a lock-free, crash-safe, O(1) allocator. Siblings forking concurrently each obtain a guaranteed unique ns-pid from the hardware exclusive-monitor without locks, file contention, or retry loops.

2. **Orphan reparenting mismatch.**
   > [!NOTE]
   > **MITIGATED**
   > Since macOS lacks a subreaper primitive and reparents orphaned processes to launchd, carrick handles this in userspace via the NsSupervisor's orphan-flag protocol (§3.6). The supervisor detects member death via `EVFILT_PROC` and marks surviving descendants as orphaned in the `MAP_SHARED` region, allowing `getppid()` to report the translated init pid `1` instantly. The ns-init's `wait4(-1)` then harvests their exit statuses from the supervisor's dead-orphans table, while launchd cleans up the host zombies.

3. **pid-translation must cover *every* pid-bearing syscall consistently, or tools see incoherent pids.** Miss one site (e.g. a `si_pid` in a `SIGCHLD` siginfo, a pid in `/proc/<pid>/stat`'s ppid field, `getpgid`/`getsid`, `procfs` `task/`) and a container gets a pid from one ns and a pid from another and crashes. Mitigation: enumerate all pid sources (grep `std::process::id()` / `libc::getppid` / `Pid`/`Pgid`/`si_pid`) and route them through one translation function; the probes must assert cross-syscall consistency, not just `getpid()`.

4. **`setpgid`/`setsid` group escape undermining teardown.**
   > [!WARNING]
   > Guest processes can use `setpgid` or `setsid` to escape the namespace init's process group, causing a naive group-based teardown (`killpg(ns_pgid, SIGKILL)`) to miss them. Mitigation: The NsSupervisor uses `killpg` only as an optimization fast path; it performs a *complete sweep* of the `MAP_SHARED` membership slots to issue individual `kill(host_pid, SIGKILL)` calls to all escapees, guaranteeing no process survives namespace teardown.

### Open questions

- **Capabilities depth.**
  > [!NOTE]
  > **RESOLVED**
  > Phase 1 implements a software-modeled `CapabilitySet` in `CredState` initialized to the Docker default `0xa80425fb` (observed). This enables `capget`/`capset` and `prctl(PR_CAPBSET_*)` to behave consistently, keeping libcap-based tools (`apt`, `dpkg`, `setpriv`) happy without requiring macOS kernel capability support.

- **Threads vs pid namespaces.** Thread tids (`ThreadRegistry`, per-process, `main_tid` == host pid) are not currently ns-translated. Does any Docker workload read another process's *thread* tid through a pid-ns boundary (`/proc/<pid>/task/<tid>`)? If so, tids need ns-aware numbering too; assume not for v1 and revisit.

- **Does the `next_pid` allocator need to recycle?**
  > [!NOTE]
  > **RESOLVED**
  > Gaps in the monotonic sequence are completely harmless. The allocator is strictly monotonic per ns, avoiding use-after-reap ambiguity and recycling complexity for v1.

- **Map-write authorization for the rootless case.** Default Docker is identity-map + initial userns, so the unprivileged single-id map rule is exercised only by guests that *themselves* `unshare(CLONE_NEWUSER)` (apt sandbox, bubblewrap, rootless buildkit). How faithfully must the "parent must have CAP_SETUID over the range" check be, given carrick doesn't truly enforce DAC? Likely "accept self-maps, enforce write-once + setgroups gate + ≤5 lines" is enough; confirm against the actual rootless tools.
