# FreeBSD/amd64 Native (DSR) Backend — Path to All 432 Conformance Probes

> Status doc. Goal: every x86_64 musl conformance probe passing under
> `--exec-backend native` on FreeBSD/amd64. This is the roadmap and the
> running scoreboard.

## Where we are

- **Baseline:** 202/432 (47%) at the start of the threading push.
- **Landed this arc:** blocking-I/O reuse, `fork()` (host fork), file-backed
  `mmap` (`MapHostAlias`). Sampled census ≈ **58%**.
- **Execution core is proven:** real `std` Rust runs natively through the real
  backend-neutral `SyscallDispatcher`; direct-branch chaining works; conditional
  fxsave landed. What remains is *breadth of servicing*, not the engine.

The exact current scoreboard (per-bucket counts) is filled in from the
reliable serial census — see **Scoreboard** below.

## Strategy principles

1. **Reuse, don't rewrite.** The native lane is an *adapter* onto the same
   backend-neutral machinery the VMM lanes feed: `SyscallDispatcher`,
   `GuestMemory`, `crate::runtime::service_syscall`. Every rung should first ask
   "does the shared path already produce this outcome?" before writing new code.
2. **The identity memory model is a cheat code.** guest VA == host VA means
   `fork` = host `fork` (COW), file `mmap` = `MAP_FIXED` at the VA, and — the key
   for this arc — a **guest thread = a host thread sharing the address space**.
   Lean on it.
3. **Measure every rung.** Re-run the census after each rung; a rung is not done
   until the OK count rises and *no previously-OK probe regresses*.
4. **Clean-room always.** man-pages + Docker oracle only. Never Linux/glibc source.

## The buckets → rungs, ordered by ROI

From the reliable serial census of all 432 targets (`docs/native-x86-census.tsv`),
**baseline 250 OK (58%)**. Actionable failing buckets, ordered by (probes
unlocked) × (whether it unblocks later rungs), against implementation cost:

| Rung | Bucket (census tag) | Probes | Unblocks | Cost |
|------|--------|-------|----------|------|
| **A** | CloneThread threading core (`OUT:CloneThread`) + futex (`HANG` futex\*, `OUT:WaitOnSharedWord`) | **44** + ~6 | most of the tail | High (concurrency model change) |
| **B** | Container networking (`EMIT`/`hlt`, all `bridge_*`) | **24** | — | High (rtnetlink + `/proc/net` + `/sys/class/net` + DNS) |
| **C** | Faults: protection enforcement + diverse SIGSEGV (`FAULT:signal11`) | **56** | — | Medium (many may already be *correct* faults — triage first) |
| **D** | No-progress: guest-generated code + cflow gaps (`NOPROG`) | **15** | — | Mixed (guest-JIT is Medium-High; cflow forms are small) |
| **E** | `execve` in-process image replacement (`OUT:Execve`) | **7** | — | Medium |
| **F** | Long tail (remaining `HANG/OTHER`, `SigReturn`) | remainder | — | Iterative |

Rung A is first: largest single actionable bucket *and* the infrastructure
(shared thread-runtime, per-thread JIT, threaded dispatch) that the futex probes
and much of the tail depend on.

### Bucket triage — actual root causes (verified, not guessed)

- **B / `EMIT` (24, `bridge_*`)** — *not* an emitter gap. The unlowered
  "instruction" is `f4` = **`hlt`**, which is musl's `a_crash()` on x86_64. The
  `bridge_*` probes call `getifaddrs`/rtnetlink, read `/proc/net` + `/sys/class/net`,
  and resolve DNS; with no container network identity in the native lane,
  `eth0_ipv4()` finds nothing and the probe aborts into `hlt`. So this bucket is
  **container networking**, a large rung. *Sub-task worth doing regardless:* lower
  a userspace `hlt` to a clean guest `SIGSEGV` (Linux #GP semantics) so it faults
  the guest instead of aborting the translator — hardening, but it will not by
  itself flip these probes.
- **D / `NOPROG` (15)** — three sub-causes: (1) **guest-generated executable
  code** — `mprotectexec` mmaps a page, marks it PROT_EXEC, writes code, and jumps
  in; the translator only knows the ELF PT_LOADs, so the jump target (`0x6000003000`)
  reads empty. Fix: translate-on-demand from *live guest memory* (the arenas/mmap
  regions), not just the static image. (2) **missing `cflow` branch form** —
  `killrt` hits "branch form … not lowered yet" in `cflow::resolve`; small,
  additive. (3) **execve churn** — stale segments after exec (needs Rung E).
- **C / `FAULT:signal11` (56)** — triage before coding: many are probes whose
  *designed* behavior is to fault (protection tests), which the coarse census tags
  as failures. Split "faulted as designed" from "we broke a working program."

> **Triage note on Rung C (56 faults):** a `FAULT:signal11` census tag means the
> guest took SIGSEGV — for many probes (`protnone*`, `bsd_signal_xlate`, the
> NOT-GATED protection tests) that is the *correct* behavior the probe asserts,
> so they may already pass under the probe's own success criteria and only look
> like failures to the census's coarse classifier. Rung C starts by splitting
> "faulted as designed" from "we faulted a working program," and only the latter
> is real work. Expect the true Rung-C workload to be well under 56.

> **`build`/`deps`/`examples`** in `HANG/OTHER` are cargo artifact directories in
> the release dir, not probes — census noise, excluded from real counts.

---

## Rung A — Threading core (CloneThread + Futex)

**Model.** A guest `clone(CLONE_VM|CLONE_THREAD|…)` becomes a real host thread
that shares the (identity) address space. No memory translation is needed — the
new thread's stack, TLS, and code are already mapped at their guest VAs.

**Direct model: `native_darwin.rs`** (the aarch64 native DSR lane is already
fully multi-threaded — it is the port source, *not* the VMM `run_threaded_loop`).
Shared primitives in the `carrick-thread` crate (`crate::thread`) are reused
**verbatim**; only the run-loop/spawn scaffolding is ported.

**Reuse map (exact targets):**
- `crate::thread::ThreadRegistry` (`carrick-thread/src/thread.rs:166`) —
  `register_child(clear_child_tid) -> ThreadId`, `exit(tid) -> bool` (was-last),
  `is_live`/`live_count`. `ThreadId::main_from_host_pid()` already used at
  `native_freebsd.rs:524`.
- `crate::thread::FutexTable` (`thread.rs:651`) —
  `wait_prepared_for_thread(wait, timeout, tid, &interrupted)`, `wake(addr, n)`,
  `requeue(...)`. `FutexWait { addr, generation }` arrives *inside* the
  dispatcher outcome (lost-wake generation already captured).
- Port `NativeThreadRuntime` (`native_darwin.rs:3129`) → `FreebsdThreadRuntime`:
  `{ tid, registry: Arc<ThreadRegistry>, futex: Arc<FutexTable>, waiter,
  threads: Arc<Mutex<Vec<JoinHandle>>>, … }` with `new_current()` + `sibling(tid)`.
- Port `spawn_clone_thread` (`native_darwin.rs:3317`) and `wait_native_futex`
  (`:4647`).

**The dispatcher already emits the outcomes** (`dispatch/mod.rs`): `CloneThread`
(`:1292`), `ThreadExit` (`:1303`), `FutexWait` (`:1321`), `FutexWaitv` (`:1325`),
`Execve` (`:1234`). Today they fall into the `other => Step::Fault(...)` arm at
`native_freebsd.rs:940` — Rung A is largely about *handling* them there.

**What has to change in `native_freebsd.rs`:**

1. **Shared thread-runtime.** `Arc` the `SyscallDispatcher` (change
   `run_static_x86_elf(mut dispatcher: SyscallDispatcher …)` at `:486` to build an
   `Arc<SyscallDispatcher>`), plus shared `Arc<FutexTable>` + `Arc<ThreadRegistry>`
   in a `FreebsdThreadRuntime`.
2. **Per-thread JIT + block cache.** Today the block cache
   (`HashMap<u64,(exec,has_edges,uses_fpu)>` at `:573`), the JIT region (`:509`),
   and the cursor (`:559`) are per-run local state assuming a single thread. Give
   **each host thread its own JIT region + block cache + snapshot + `guest_fsbase`**.
   The identity code pages are shared and immutable, so re-JITing the same guest
   block per-thread is correct (just not maximally compact).
   **Fault-shim wrinkle (resolved):** `carrick-native-freebsd/src/fault.rs` tracks
   a *single* `[CODE_BASE, CODE_BASE+CODE_LEN)` region (`fault.rs:64`), and the
   handler already reads the *per-thread* fault record via `mc_r15`, so the only
   gap is region coverage. Fix without touching the signal handler: carve all
   per-thread JIT slices from **one contiguous code-cache reservation** and
   register that single covering span once. Each thread bump-allocates within its
   own slice (own cursor); the RW-alias write model is just an offset from the
   shared `write_base`.
3. **Drop `RUN_LOCK`.** It serializes in-process runs and is incompatible with
   concurrent guest threads. Replaced by per-thread isolation (own JIT) + the
   `Arc` shared runtime.
4. **Threaded dispatch.** Switch the run loop to the thread-aware servicer that
   understands `CloneThread`, `FutexWait/FutexWake`, `ThreadExit` (thread exits
   without `exit_group`), and `set_tid_address` / `CLONE_CHILD_CLEARTID` (wake the
   clear-tid futex on thread exit).
5. **Thread spawn.** On a `CloneThread` outcome: allocate the new thread's
   `X86DsrContext`, seed a snapshot (rax=0, rsp=child stack, fs=child TLS,
   rip=resume), spawn a host thread that enters the per-thread run loop, register
   the TID.

**Risks / watch-items:**
- The FreeBSD `sigaction` fault shim must be process-wide and reentrant across
  threads (it already installs process-global handlers; verify the fault-record
  slot is per-thread via `r15`, not global).
- Signal delivery to a specific guest thread.
- Teardown: `exit_group` from any thread must stop *all* threads.

**Concurrency-model finding (verified).** The single-thread path calls
`crate::runtime::service_syscall` → `dispatcher.dispatch(&mut self, …)`. That is
**not** shareable across threads. `native_darwin` instead drives
`dispatcher.dispatch_threaded(&self, …)` (interior-mutable, thread-safe) via
`dispatch_native_syscall` (`native_darwin.rs:3774`/`:4133`, `dispatch_threaded`
call at `:4155`/`:4165`) with an `Arc<SyscallDispatcher>`. So Rung A's servicer
must move from the `&mut dispatch` path to the `dispatch_threaded` path — this is
the load-bearing change and the main regression risk (blocking waits are then
serviced by the threaded machinery, not the local `ThreadWaiter` loop).

**Implementation checklist (turn-key, in dependency order):**

1. **Extract the run loop.** Pull `native_freebsd.rs:555–806` into
   `run_x86_thread(start: ThreadStart, shared: &SharedRun, rt: &mut FreebsdThreadRuntime)`,
   where `ThreadStart::{ Initial { entry, rsp }, Detached { snapshot, fsbase } }`
   (copy `NativeThreadStart`, `native_darwin.rs:2026`). Keep behavior identical
   for the `Initial` case first; build + run the 4 integration tests + a census
   spot-check; commit while still single-threaded and green. *(De-risks the
   mechanical extraction from the semantic change.)*
2. **Switch the servicer to `dispatch_threaded`.** Replace the local
   `service_syscall`'s `crate::runtime::service_syscall(&mut dispatcher…)` with a
   `dispatch_native_syscall`-style call on `Arc<SyscallDispatcher>`. Re-census —
   this is where a regression would show; gate on the OK count not dropping.
   Commit.
3. **`FreebsdThreadRuntime`** (port `NativeThreadRuntime`, `native_darwin.rs:3129`):
   `{ tid, registry: Arc<ThreadRegistry>, futex: Arc<FutexTable>, waiter,
   threads: Arc<Mutex<Vec<JoinHandle<()>>>, … }` + `new_current()` + `sibling(tid)`.
4. **Single contiguous code cache.** Reserve one large JIT region up front,
   register it once with `fault::register_code_region`, and hand each thread a
   non-overlapping slice `(exec_base+off, len)` with its own cursor/cache/pending.
   No fault-shim change.
5. **`spawn_clone_thread`** (port `native_darwin.rs:3317`): `register_child`,
   `inherit_thread_signal_mask`, write parent/child tids, clone the snapshot with
   `RAX=0` / `RSP=stack` / `guest_fsbase=tls`, `std::thread::Builder::spawn` the
   per-thread `run_x86_thread(ThreadStart::Detached…)`, readiness `sync_channel`.
6. **Handle the new outcomes** at `native_freebsd.rs:940` (replace the `other =>
   Step::Fault`): `CloneThread → spawn_clone_thread`; `FutexWait`/`FutexWaitv →
   futex.wait_prepared_for_thread`; `ThreadExit →` registry `exit` + clear-tid
   futex wake (port `finalize_native_thread_exit`, `native_darwin.rs:1903`);
   `exit_group` from any thread stops all.
7. **`RUN_LOCK` stays at *run* granularity** (arenas + fault shim are still set up
   once per run) — do **not** hold it per guest thread. Verify with a CloneThread
   probe that two guest threads run concurrently.

**Done when:** the CloneThread + futex probes pass and the 4 integration tests +
prior OK probes still pass (run the full census, not just `--test-threads=1`).

---

## Rung B — `hlt`-trap cluster

~21 `bridge_*`/`perf_*` probes reach a `hlt` trap guard. `hlt` in guest code is
almost certainly *not* real — it indicates control flow ran off into a region we
mis-decoded or mis-serviced (a syscall we return wrongly, sending the guest into
an error path that executes garbage). Approach: pick one representative probe,
trace with the loud breadcrumbs + dtrace USDT + gcore/JIT-disasm playbook in
AGENTS.md, find the divergence, fix the underlying servicing bug. Likely a
cluster with 1–3 shared root causes.

## Rung C — Protection faults + diverse signal-11

~25 probes. Two sub-groups:
- **Protection enforcement:** the identity model maps guest pages with host
  perms; guest `PROT_NONE`/RO accesses that *should* fault currently may not
  (the "NOT-GATED" tests expect a SIGSEGV). Need to honor guest-requested
  protections on the guest's own accesses.
- **Diverse SIGSEGV/SIGBUS cases:** null deref, unmapped access, misalignment —
  verify the fault shim reports the right signal + siginfo to the guest handler.

## Rung D — `execve`

~5 probes. In-process image replacement: on `execve`, tear down the current JIT,
reload the target static-PIE ELF into the identity space, rebuild the initial
stack/auxv, reset the run loop. The loader (`load_static_pie`,
`build_initial_stack`) already exists — execve re-drives it.

## Rung E — Long tail

Whatever the post-A–D census surfaces. Iterate: census → bucket → fix → re-census
until 432/432.

---

## Testing & census methodology

- **Reliable census:** `scratchpad/census.sh` runs each probe **serially** with
  `timeout -s KILL 6` and a `pkill -9 -f native_run` reap after each probe (fork/
  thread probes orphan children; parallel runs accumulate 1 GiB arenas and OOM,
  which is what stalled earlier parallel censuses at ~278). Output classified into
  OK / OUT:<outcome> / NOPROG / FAULT:<sig> / EMIT / HLT / HANG. ~10–15 min for
  all 432.
- **Regression gate:** the 4 integration tests in
  `crates/carrick-runtime/tests/native_freebsd_x86.rs` plus the OK set from the
  prior census must not shrink.
- **Never run vmm on this rig.** Native is default; the census invokes
  `native_run` directly.

## Definition of done

432/432 conformance probes OK under `native_run`, the integration suite green,
macOS reference lane still compile-clean (darwin cross-check), and a clean census
with zero HANG/OTHER.

## Scoreboard

Reliable serial census, all 432 targets. Raw data: `docs/native-x86-census.tsv`.

| Date | OK | Notable |
|------|-----|---------|
| baseline (this census) | **250 / 432 (58%)** | blocking-I/O + fork + file-mmap landed |

Failing-bucket breakdown at baseline:

| Census tag | Count | Rung |
|------------|-------|------|
| `FAULT:signal11` | 56 | C (triage first — many are correct faults) |
| `OUT:CloneThread` | 44 | A |
| `HANG/OTHER` | 33 (−3 junk) | A (futex) / F |
| `EMIT` | 24 | B |
| `NOPROG` | 15 | D |
| `OUT:Execve` | 7 | E |
| `OUT:WaitOnSharedWord` | 2 | A (shared futex) |
| `OUT:SigReturn` | 1 | F |

_Updated after each rung._
