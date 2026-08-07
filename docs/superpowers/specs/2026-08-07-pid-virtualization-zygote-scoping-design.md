# PID virtualization and the zygote: a scoping pass

**Status:** proposed 2026-08-07 (user-directed). Feasibility + sizing pass —
NOT an implementation. Deliverable is a go/no-go with a phased sketch, and
NO-GO is a first-class allowed outcome.
**Scope:** Darwin/aarch64 native backend. Two separable subjects with a
dependency between them (see §2).

## 1. Why this, and the honest ceiling first

The roadmap records the zygote as **structurally impossible under two
standing constraints** (roadmap §3 correction): *(a)* the 2026-07-13
libdispatch finding forces a real `exec` before a forked child may create
threads (CoreFoundation/libdispatch state is fork-unsafe), and *(b)* **PID
preservation** — guest PID == host PID — forbids handing a guest off to a
pooled process that already has a host PID.

This pass exists because **PID virtualization removes constraint (b)
outright**, leaving (a) as the sole blocker — and (a) may be dissolvable on
the native lane specifically, because the guest runs its own code and it is
*carrick's* runtime, not the guest, that pulls in libdispatch/CF. That is the
central technical question below.

**The ceiling, stated up front so the pass is aimed honestly.** Ablation
rung 4 (`docs/perf-results/2026-08-07-ablation-ladder.md`) measured the entire
exec chain at **7.2 ms/exec ≈ 5.4% of the cold build**. That is the hard
upper bound on *all* exec-chain work, zygote included. So:

- On the canonical `go build`, a perfect zygote is at most a ~1.05x lever.
  **The pass must not sell it as a go-build 3x lever — it cannot be one.**
- Its real prize is on **exec-dominated shapes** (the 20-exec `compile -V`
  micro was 72.16x; there per-exec cost is most of the wall) — the pass sizes
  the prize *per shape*, not just on the build.
- **PID virtualization has value independent of the zygote**: it is the same
  guest-PID↔host-PID decoupling that a shared-VM or process-pool model would
  also require, and it retires a quoted impossibility. The pass must weigh
  PID-virt on its own merits even if the zygote prize is marginal.

## 2. The two subjects and their dependency

- **PID virtualization** — decouple guest PID (`NsPid`) from host PID
  (`HostPid`). carrick already has these typed domains from the
  typed-interfaces migration; the question is how *complete* the existing
  translation is versus how much still assumes identity.
- **The zygote** — a warm pool of pre-forked, past-dyld/CF-init host
  processes, each claimed on demand, assigned a fresh guest PID, handed a new
  guest image *without* a fresh `exec`, run, and recycled or discarded.

The zygote **depends on** PID virtualization (to assign identity) AND on
dissolving constraint (a) (to run a new image in-process). PID virtualization
does not depend on the zygote. Report them separably.

## 3. The questions the pass must answer

### 3a. The PID-preservation dependency surface (enumerate it, don't estimate)

Every place carrick relies on guest PID == host PID is a place virtualization
must translate. Enumerate against the code, each with file:line and a verdict
(already-translated via `NsPid`/`HostPid` / assumes-identity / needs-work):

- `getpid`/`getppid`/`gettid`; `/proc/self`, `/proc/<pid>/*`.
- Signal delivery: `kill`, `tgkill`, `rt_sigqueueinfo`, `si_pid` in siginfo
  (the kill-cluster work already touched `si_pid` side-channels — how much is
  already virtual?).
- Wait: `wait4`/`waitpid`/`waitid`/`waitid`+`CLONE_PIDFD` — does carrick
  `waitpid` on host PIDs and map the result back to a guest PID?
- `clone`/`fork`/`vfork` return values; `CLONE_CHILD_SETTID`/`CLEARTID`
  (writes a **TID** to guest memory — must be the guest TID); `CLONE_PARENT_SETTID`.
- Process groups / sessions: `setpgid`, `getpgid`, `setsid`, `getsid`,
  `tcsetpgrp` (the interactive job-control work).
- `pidfd_open`/`pidfd_send_signal`/`pidfd_getfd`.
- Robust futexes and `set_robust_list` (the list holds addresses, but the
  futex value carries a TID in `FUTEX_*_PI` and `CLONE_CHILD_CLEARTID`).
- `prctl(PR_SET_*)`, `ptrace` (PID-heavy — Phase-1 ptrace scope).
- The **event ring** and `carrick trace` predicates — do they key on host PID?
  (This is where host-native *integration* meets the premise change — see 3d.)

Output: a table sized as "N sites total, M already `NsPid`/`HostPid`-clean,
K assume identity" — the M/N ratio is the strongest single input to the
go/no-go, because it says whether virtualization is a finish or a rewrite.

### 3b. The zygote crux — can a pooled process run a new image without `exec`? (the load-bearing question)

Constraint (a) says a forked child cannot create threads before a real `exec`
because libdispatch/CF state is corrupt post-fork. But the zygote wants a
pooled member to adopt a *new guest image* in-process. Determine, against the
actual post-fork guest-execution path (`native/fork_child.rs`, the native
run loop, `resume_guest_from_capsule`):

1. Does the native guest-execution + syscall-servicing path touch libdispatch
   or CoreFoundation **at all** after the guest starts? The guest runs its own
   code; carrick services `svc` traps. If that servicing path is CF/libdispatch
   -free, a pooled member could adopt a new image without the forbidden thread
   creation. **Verify — do not assume.** Find any CF/libdispatch call reachable
   from steady-state syscall dispatch (fork-unsafe-CoreFoundation memory is the
   prior art).
2. If the path is NOT clean, what pulls CF/libdispatch in, and can it be
   isolated to a pre-fork init that the pooled member inherits already-done?
3. What must be *reset* in a pooled member between guests (dispatcher state,
   fd table, the guest arena, signal handlers, TLS, the event ring)? The
   `native/fork_child.rs` post-fork reset already exists for the fork path —
   how much of it is the reset a zygote hand-out needs?

If (1) is NO and (2) is NO, the zygote stays blocked and PID-virt's value is
prerequisite-only — a legitimate and important NO-GO-for-zygote.

### 3c. Sizing the zygote prize against the measured breakdown

The exec-cost decomposition (`2026-08-03-native-exec-fixed-cost-decomposition.md`,
summarized in AGENTS.md): ~8.5 ms/exec = ~1.8 ms any-binary floor + ~1.6 ms
dying-guest teardown + ~0.9 ms CF/HVF/dtrace initializers + ~0.8 ms
carrick-binary premium + ~3.2 ms carrick's own code. A zygote skips `exec`
entirely, so it *removes* the parts a pooled member has already paid (dyld,
CF/dtrace init, binary premium) and *replaces* them with: pool-claim +
guest-PID assign + new-image load (mmap, not exec) + inter-guest reset (3b.3)
+ pool replenishment. Estimate the replacement cost and therefore the
**addressable fraction of the 7.2 ms**. A zygote that hands out a member in
6 ms beats 8.5 ms marginally and is not worth the complexity; one that hands
out in 2 ms is real. Give the number per shape (build vs 20-exec micro).

### 3d. The fork-coherence home and the identity cost

- **Fork coherence:** the guest-PID↔host-PID table must survive guest `fork`
  (house rule: in-process `HashMap` is not fork-coherent — it silently
  diverges). Where does it live — durable memory, a shared mapping, host-kernel
  bookkeeping? Cite the durable-memory work as the candidate home and say what
  fits.
- **Identity cost:** virtualizing PIDs breaks "the guest process appears as
  host PID N." State exactly what host-native integration gives up (host tools
  attaching by PID, `carrick trace`/event-ring keying, `ps` correspondence) and
  whether a *stable mapping* (guest PID ↔ host PID, both queryable) preserves
  enough of it. This is the premise's real price and the pass must name it.

## 4. Method

- **Read + small probes only. No implementation, no zygote, no PID-table
  build.** The dependency-surface enumeration (3a) is a code audit. The zygote
  crux (3b) is a code audit plus, if cheap, a throwaway probe that fork+adopts
  a trivial second image in a warm process and reports whether it runs or dies
  in CF/libdispatch. The prize sizing (3c) is arithmetic over the committed
  decomposition plus a micro-timing of the replacement steps if a probe is
  cheap.
- Any probe: quiet host, `CARRICK_RUN_ID`, `scripts/sudo/kill.sh` only, never
  carrick‖Docker, receipts under `target/perf/pidvirt-scope/`, foreground
  blocking calls.
- Cite `NsPid`/`HostPid` usage from the real code, the 2026-07-13 self-reexec
  design, the exec decomposition, and rung 4 — do not re-derive them.

## 5. Deliverable

`docs/superpowers/specs/2026-08-07-pid-virtualization-zygote-feasibility.md`:
- the 3a dependency-surface table with the M/N clean ratio;
- the 3b verdict on the zygote crux (in-process image adoption: possible /
  blocked-and-why);
- the 3c prize sizing per shape, against the 5.4% exec ceiling;
- the 3d fork-coherence home and the itemized identity cost;
- **two separate go/no-go calls** — one for PID virtualization (weighed on its
  own prerequisite value), one for the zygote (weighed on its measured prize) —
  each with a phased implementation sketch if GO and the smallest first
  experiment; NO-GO fully allowed for either or both, with the reason.

## 6. What would make this a GO despite the 5.4% build ceiling

- The zygote's addressable prize is large on the exec-dominated shape AND
  those shapes matter to the product (CI, shell pipelines).
- PID virtualization's M/N clean ratio is high (a finish, not a rewrite) AND
  it is a confirmed prerequisite for a route the project intends to pursue
  (micro-vmm process multiplexing, shared-VM tiering).
- The zygote crux (3b) resolves POSSIBLE — a native syscall-servicing path
  that is CF/libdispatch-free is a significant unlock beyond the exec number.

## 7. What would make it a NO-GO

- 3a shows PID preservation is woven through un-typed identity assumptions
  (low M/N) — a multi-week rewrite for a 5.4%-ceiling'd prize with no committed
  downstream consumer.
- 3b resolves BLOCKED (CF/libdispatch unavoidably in the servicing path) — the
  zygote stays impossible; PID-virt survives only if 6's prerequisite case holds.
- 3c shows the replacement cost eats most of the 7.2 ms — no prize even where
  exec dominates.
