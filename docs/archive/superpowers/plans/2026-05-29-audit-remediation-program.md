# Audit Remediation Program — Implementation Plan

> **For agentic workers:** This is a multi-milestone PROGRAM, not a single task plan.
> Each milestone is an independently green, reviewable unit (milestone-scoped
> commit(s)). Execute milestone-by-milestone with the verification spine below.
> Per-milestone bite-sized task lists are generated just-in-time at execution (the
> executor is autonomous). Source of truth for findings:
> `docs/audits/2026-05-29-systems-audit-augmented.md`.

**Goal:** Drive every finding in the augmented systems audit to a verified fix so
Carrick is robust against an untrusted/buggy Linux guest and faithful to the Linux
ABI — ready for public release.

**Architecture:** Fix the bug *class* (root cause), then add a static guard
(Semgrep/clippy) so it cannot recur; each instance is locked by a deterministic
conformance probe (carrick vs Docker `linux/arm64`, line-diffed). Milestones are
sequenced by risk-reduction × dependency.

**Tech Stack:** Rust (workspace, edition 2024), Hypervisor.framework, conformance
probes (static aarch64-musl ELFs), Docker oracle, Semgrep.

---

## The verification spine (every change, no exceptions)

This is what makes the program *robust*. For each fix:

1. **Probe-first (TDD).** Write/extend a deterministic probe in
   `conformance-probes/src/bin/<name>.rs` (booleans/relationships only — never
   times/pids/addrs). For crash-class, run the dangerous op in a forked child and
   report `WIFEXITED/WIFSIGNALED`. For raw-asm faults, a fixture in
   `fixtures/linux-aarch64-hello/src/`.
2. **Confirm it reproduces.** Build (`build-probes.sh` / `build-linux-fixtures.sh`)
   and run under the CURRENT binary: it must **DIFF** (or carrick must crash/hang).
   A probe that already MATCHES proves nothing — fix the probe or the premise.
3. **Fix the root cause.** Prefer the Darwin-native primitive over emulation.
   Reuse existing helpers; match surrounding code.
4. **Verify.** `./scripts/build-signed.sh` → re-run the probe → **MATCH**.
5. **Regression subset.** Run ~8 probes exercising the touched path (read/recv/
   fork/signal/fs as relevant) via `scripts/run-probe.sh` — all MATCH.
6. **Adversarial review.** A skeptic subagent reads the diff + cited code and tries
   to refute correctness / find a regression or an unhandled edge. Address findings.
7. **Add the guard** (once per class): a Semgrep rule and/or clippy lint so the
   class cannot return. (Guards land in M0; later milestones extend them.)

**Per-milestone gate (before the commit):** `build-signed` → `build-probes` →
`cargo test --release -p carrick-cli --test conformance conformance_probes` MUST be
fully green (the harness re-signs the binary and runs every probe under carrick +
Docker). Then a milestone-level review subagent + a completeness critic ("what did
we miss — an unhandled errno, an untested path, a silent cap?").

**Non-negotiable invariants:** zero conformance regressions; no new
`unwrap/expect/panic/todo/unimplemented` (workspace-denied); no guest-reachable
panic or unbounded allocation introduced; LTP-overlapping items folded into
`docs/ltp-baseline/ROADMAP.md`, never duplicated; honest accounting (no silent
truncation of scope).

## Execution machinery

- **Commits, not PRs.** All work lands on a single program branch off `main`:
  `fix/audit-remediation`. Each milestone is one (or a few) well-scoped,
  conventional commit(s) with the gate result + review summary in the message.
  No `gh pr`. No push to origin unless explicitly asked — commits are local.
- **Parallel worktree lanes:** within a milestone, fixes touching *disjoint* files
  run as parallel lanes (each its own git worktree → own `target/`, built+signed in
  isolation). Probes are built once centrally and referenced by absolute path (the
  probe ELFs are carrick-source-independent), so lanes don't each re-run the docker
  probe build. Concurrency bounded (~3) by per-process RSS + HVF/Docker contention,
  NOT a hypervisor instance limit. A serial integration step then rebuilds-signed on
  the program branch and runs the full gate before the milestone commit.
- **Cross-cutting milestones run serial:** M1 (`write_guest_bytes`), M2 (`trap.rs`
  vCPU snapshot), M5 (memory arch) touch shared, high-risk files — one lane, no
  parallelism.
- Never `build-signed` while a gate/sweep reads the binary. Kill stale guests by PID
  (never the global `kill.sh`/`pkill` while sibling lanes run).

---

## Milestones

Severities/probe names reference the augmented audit. "DoD" = definition of done.

### M0 — Floor hardening + land the verified cluster  (foundation; do first, serial)

Stops the bug-classes recurring before we fix instances, and banks the work already
verified this session.

- Enable `[profile.release] overflow-checks = true` (guest-controlled integer math is
  everywhere; turns silent wraps into deterministic errors). Pair hot sites with
  explicit `checked_*`. (Defer `panic = "abort"` until guest-reachable panics are
  eliminated in M1–M3; setting it now would break the CLI's catch_unwind "GUEST
  ABORT" reporter.)
- Add static guards as a `semgrep` CI step + extend `[workspace.lints.clippy]`:
  `indexing_slicing` (warn→deny in dispatch/hvf), evaluate `undocumented_unsafe_blocks`
  and `unsafe_op_in_unsafe_fn`. New Semgrep rules: `guest-len-must-clamp`,
  `gpr-table-index`, `write-guest-bytes-perms`, `f-setfl-must-mask-status`,
  `host-errno-must-translate`, `fd-ffi-allowlist`.
- Commit the 4 already-verified fixes + their probes/fixture: `MAX_RW_COUNT` read
  clamp, `GPR_TABLE.get()`, read-past-EOF guard, `msgsnd/msgrcv` checked-add.
- **DoD:** overflow-checks on; semgrep+clippy gates green; probes `bigread`,
  `readpasteof`, `msgoverflow`, `fsetfl` (present, still DIFF until M4), fixture
  `sp_fault` in the suite; full gate green; milestone committed.

### M1 — Containment / host-robustness  (security spine; serial)

The cluster that lets a guest crash/escape the host. Highest priority for release.

- `GuestMemory::write_bytes` (the syscall path; trap.rs:3076) routes through a
  permission-checked variant that consults `mapping.perms.write` → synthesize
  `EFAULT` for a write into a non-writable mapping. Carrick-internal writes (vdso
  vvar, sigframe, bootstrap) keep calling the unchecked `inner.write_guest_bytes`.
  **Fixes `rosharedbus`** (a PROT_READ `MAP_SHARED` file alias carries
  `perms.write=false`).
- Reject `MAP_FIXED` placement into carrick-owned IPA regions (EL1 page tables,
  vector table, trampolines, shared aperture control) → `EINVAL`. Closes the static
  MAP_FIXED-into-EL1 host-corruption/escape path. (Not conformance-probe-testable —
  Linux would map there; guard with a unit test / fixture that confirms carrick
  rejects rather than corrupts.)
- Signal inject-failure (unwritable stack) → forced default-action SIGSEGV that
  terminates the whole guest thread-group with stdout/stderr flushed; sibling-thread
  error path must perform the `clear_child_tid` futex wake (else peers deadlock).
  New probe `sigbadstack` (whole-thread-group SIGSEGV → 139).
- Read-side `access_ok`-equivalent: `read(huge_count)` returns EFAULT when
  `buf+count` overflows the guest VA range (the fidelity follow-up M0 surfaced).
- **Scope correction (found during M1 design):** `mapfixed`'s full fix — making
  `MAP_FIXED|MAP_PRIVATE` over a `guest_shared` aperture region genuinely private
  (a real private remap, so the child's write does NOT reach the shared backing) —
  needs the durable-memory mapping work and MOVES TO **M5**. It stays in
  KNOWN_PROBE_GAPS until then. The `perms.write` check does NOT cover it (the shared
  aperture is writable).
- **DoD:** `rosharedbus` MATCH; `sigbadstack` → 139; MAP_FIXED-into-EL1 rejected
  (unit/fixture); no guest-reachable host *crash/corruption* remains in this class
  (`mapfixed`'s privacy-fidelity is deferred to M5, tracked).

### M2 — Fork / vCPU state fidelity  (serial; trap.rs)

- Add `[u128;32] + fpsr + fpcr` to `VcpuSnapshot`; capture via `get_simd_fp_reg`/
  `Reg::FPSR`/`FPCR` in `snapshot_vcpu`; restore via the **`set_simd_fp_reg_v` C shim**
  (NOT applevisor's `set_simd_fp_reg` — the known V-reg-zeroing ABI bug) in
  `restore_vcpu` (+ the multithreaded `rebuild_vcpu_after_fork`).
- Migrate the dispatcher's per-tid alternate signal stack (and any per-tid signal
  state that should survive fork) from old-tid → new-tid in the fork-child path.
- **DoD:** `forkfpregs`, `forkaltstack` MATCH (parent and child).

### M3 — Blocking / readiness fidelity  (parallel lanes ok)

- `pselect6`/`select` all-host path → `WaitOnFds` handoff (signal-interruptible),
  mirroring `ppoll`; honor the sigmask arg.
  - **DEFERRED (attempted, reverted): not a simple ppoll mirror.** select's fd_sets
    are input==output. The runtime's WaitOnFds completion (runtime.rs:1084) does
    `Ready`→re-dispatch (the handler re-reads the guest fd_sets, so they must be
    the ORIGINAL input) but `TimedOut`→returns `on_timeout` directly (so the sets
    must already be ZEROED — Linux zeroes them on timeout). A plain handoff can't
    satisfy both: preserving input regresses `selecttimeout` (not-ready bit stays
    set after timeout); zeroing first breaks the readiness re-dispatch. Correct fix
    needs either (a) carrick-side per-tid snapshot of the original fd_sets restored
    on re-dispatch + zeroed write for timeout, or (b) runtime re-dispatch-on-timeout
    for select so the handler can zero+return 0. `pselecteintr` stays XFAIL until then.
- `SO_RCVTIMEO`/`SO_SNDTIMEO` honored on blocking recv/send (thread the per-socket
  timeout into the `WaitOnFds` timeout).
- `rt_sigsuspend` waits on the per-tid `THREAD_PENDING` set (tkill/tgkill wakeups),
  not just the process-global slot.
- epoll overflow queue (`pending_ready`) keyed by the originating fd, not guessed
  from `epoll_data`.
- **DoD:** `pselecteintr` MATCH + new probes for the recv-timeout, sigsuspend-tkill,
  and epoll-DEL-with-data!=fd invariants.

### M4 — ABI / errno fidelity  (parallel lanes — many disjoint files)

Each its own probe; fold LTP overlaps into ROADMAP. Items: F_SETFL mutable-status
mask (`fsetfl`); `mremap` reject/implement FIXED/DONTUNMAP; `io_uring_enter` bound by
`to_submit` + reject unsupported flags + route iovecs through the central
`read_iovecs`; `waitid` errno translation + RUSAGE_CHILDREN/`tms_cutime` accounting;
`LinuxSysinfo` field padding (2-byte) vs Linux aarch64; `recvmsg`/`recvfrom`
`MSG_TRUNC` + `msg_controllen`; termios `c_cflag`/`c_iflag` bit translation
(CSIZE/CSTOPB/parity, IXON/IXOFF); `timer_settime` `TIMER_ABSTIME` + timespec
validation; `mprotect` PROT_EXEC→UXN/PXN (NX enforcement) + arena free-list occupancy.
- **DoD:** a probe per item, all MATCH; relevant LTP tests re-swept (no regression,
  net new MATCHes recorded in BASELINE).

### M5 — Memory architecture (durable)  (serial; design pass first)

Align with `docs/superpowers/specs/2026-05-26-durable-memory-architecture-design.md`
(Plans C/D). Remove the residual late-`hv_vm_map` `MapHostAlias` cases + the alias
IPA/dup-fd leak on `munmap`; make guest `mprotect` enforced beyond the private arena
(image/heap/shared aperture) at the stage-1 boundary. Also: `MAP_FIXED|MAP_PRIVATE`
over a `guest_shared` aperture region must allocate a genuine private backing so the
child's write does not reach the shared pages (the `mapfixed` finding, moved here
from M1). Open with a judge-panel design review before coding (high blast radius).
**DoD:** the durable-memory probes + `mapfixed` MATCH + the mm LTP cluster advance;
no late stage-2 mutation after vCPUs exist for ordinary ops.

**STATUS (2026-05-29): probed deliverable DONE; architectural remainder tracked.**
Landed (commit on `fix/audit-remediation`): a boot-mapped PRIVATE overlay aperture
(`LINUX_PRIVATE_OVERLAY_BASE`, `shared:false` → fork-snapshotted per-process) +
`MAP_FIXED|MAP_PRIVATE|ANON` over a shared-aperture VA now carves an overlay slot
and repoints the VA's stage-1 leaf (`GuestMemory::repoint_private` →
`map_aliased`+`pt_edit_and_flush`) — **stage-1 only, zero new post-vCPU
`hv_vm_map`**. Probes `mapfixed` (child-repoints-after-fork) and `mapfixedfork`
(parent-repoints-then-forks; bidirectional COW isolation) both MATCH;
`KNOWN_PROBE_GAPS` is now empty (zero XFAILs). mm LTP: `mmap01`/`mmap09`/
`munmap01` MATCH (no regression). Design chosen via a 3-way judge-panel review
(workflow `wf_a5c73fa7-79e`): identity-mapped overlay (no IPA collision), Design A
+ B's correctness points.

**Durable-memory remainder (status after the 2026-05-29 follow-up session):**
1. **Late-`MapHostAlias` removal** — STILL OPEN; splits in two:
   - **High-VA anon** (`mem.rs:438` → `trap.rs:1638`, Rosetta's translation
     arena + any guest mmap ≥1 TiB): the *mechanism* (boot-map the 64 GiB
     `LINUX_ALIAS_IPA` window, then `map_aliased`+seed per mmap, zero post-vCPU
     `hv_vm_map` — the M5 overlay pattern) was IMPLEMENTED and ATTEMPTED
     (2026-05-29) and the `forkhighva` probe MATCHed. **But it was REVERTED: it
     broke basic dynamic guests** (`carrick run debian:stable /bin/echo` →
     `hv_vm_map alias ipa=0x1800000000 failed 0xfae94001`, and the conformance
     gate hung 51 min). ROOT CAUSE — a real design flaw the design pass missed:
     the boot anon aperture occupies `[LINUX_ALIAS_IPA_BASE, +64 GiB]`, but the
     OUT-OF-SCOPE MAP_SHARED-file arm (`mem.rs:335`, kept its late `hv_vm_map`)
     reserves its IPA from the SAME `alias_ipa_next` bump arena → its runtime
     `hv_vm_map` now OVERLAPS the boot aperture → HVF double-map error. **Fix for
     the future: give the boot anon aperture its OWN IPA window disjoint from the
     file-arm arena** (split `alias_ipa_next` into two ranges, or move the file
     arm to a separate IPA region), then the anon-aperture+`map_aliased` approach
     works. Still warrants a dedicated effort with Rosetta/`forkhighva` testing.
   - **MAP_SHARED file** (`mem.rs:335` → `trap.rs:1638`): the hard case and an
     UNSOLVED research item. The late map exists *because* the design needs the
     file's live page cache at an IPA; a pre-mapped anon aperture can't provide
     live file coherence, and host `MAP_FIXED`-over-aperture is unproven under
     HVF (stage-2 likely pins host-physical at `hv_vm_map` time). The durable
     spec defers this to the **Mach VM remap probe (Plan 5)**; no proven
     no-late-map coherent mechanism exists today. Documented gap, not a point fix.
2. **mprotect NX/UXN enforcement** — **PARTIALLY DONE (commit 87c4775).** W^X/NX
   is now enforced for the anonymous **mmap arena**: arena boot blocks default
   UXN=1 (non-exec), `mmap`/`mprotect` honor PROT_EXEC via `protect_range`
   (probe `mprotectexec` MATCHes all 4 cases). Chosen over the naive
   flip-on-mmap design, which dense-split the whole arena → PT-pool exhaustion →
   guest malloc abort (caught by the gate). REMAINDER: NX is arena-scoped; the
   heap/shared-aperture/overlay/stack still default executable, and guest
   `mprotect` on those non-arena ranges is still skipped — enforcing W^X there
   needs per-region UXN in the boot identity map ("mprotect beyond the arena").
3. `MAP_FIXED|MAP_PRIVATE` of a FILE over a shared-aperture VA (anon handled);
   lazy/fault-driven file COW (eager seed used); syscall-path read/write/futex
   *directly* on an overlaid VA (resolves to the shared mapping — the guest-CPU
   -store path, i.e. the real bug, is fixed; a shadow `HvfMappedRegion` was
   rejected because it would double-map the overlay IPA on a later fork).

### M6 — P3 polish + remainder  (parallel lanes)

`linkat` AT flag (define `AT_SYMLINK_FOLLOW`, validate it); `clock_getres` per-clock
resolution; SI_USER siginfo `si_pid`/`si_uid` (extend `LinuxSiginfo`); `clone`/`clone3`
`exit_signal` threaded to child-exit; `cred_ipc` `/tmp/carrick-cred-<pid>` isolation
(0600 + owner check + staleness); raw `mkfifoat`/`fchmodat` cap-std symlink-escape
guard; TTY ioctls (TIOCSWINSZ on stdio, FIONREAD on pty, set-side errno); SIGWINCH
relay rollback guard + checked `sigaction`; wait-fd pinning fallible (`OwnedFd`);
`shmat` addr/flags compat-gap; fork-quiesce poison `.expect()` audit. **DoD:** a probe
or explicit compat-gap note per item; full gate green.

---

## Tracking & honesty

- A milestone is "done" only when: its probes MATCH, the full gate is green, the
  review + completeness critic pass, and it is committed on `fix/audit-remediation`.
  A MATCH without an owning probe is not done.
- Distinguish, in every milestone commit message: fixed-and-probed / deferred-with-
  reason / host-limitation (macOS cannot) / LTP-jitter-excluded (individually
  confirmed).
- `docs/audits/2026-05-29-systems-audit-augmented.md` is updated as items land.
