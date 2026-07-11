# Native Darwin Backend Handoff

Date: 2026-07-11

Branch: `codex/architecture-evidence-gates` (fast-forwarded onto `main` at
campaign close).

Detailed local ledger: `.superpowers/sdd/progress.md` (git-ignored). This file
is the tracked continuation snapshot.

## Goal Status: PROBE TARGET MET

> Reach 100% conformance probes and more than 15% strict LTP parity on the
> native16k Darwin backend; communicate linux4k incompatibility to users.

| Gate | Result | Evidence |
| --- | --- | --- |
| native16k musl probes | **376/376 PASS (100%), measured** | `/tmp/carrick-native16k-probes-20260711-round11.log`, 228s, exit 0 |
| strict clean LTP parity | 829/1492 (55.6%) — round-1 authority, >15% met | `/tmp/carrick-native16k-ltp-round1.jsonl` |
| fork benchmark (all 3 gates) | PASS — fork p50 1.53x host (gate 2x), p95 1.36x (gate 3x), fork_exec 2.63x faster than HVF | `docs/2026-07-10-native-fork-benchmark-evidence.md` |
| linux4k user statement | accurate (README page-profile section; MT shapes are typed rejections) | commit 58d858db |
| `just ci` | run at campaign close (see final commits) | — |

The gated musl set grew 374 → 376 rows during the campaign (new probes
`execfromthread`, `vforkexecthread`). GNU remains a report-only lane
(368/8 at round 11, improved from 344/27 at round 6).

**Caveat for the next session:** the strict-LTP number is the 2026-07-10
round-1 authority; ~45 commits landed after it. The probes and unit suites
say nothing regressed, but a fresh full LTP campaign is the right next
validation before quoting the LTP number externally. A signed live
"real workload" demo (beyond the probe/benchmark batteries) was also not
re-run at close.

## What Landed (2026-07-10 → 2026-07-11, ~35 commits cf9dfd1c..HEAD)

1. **Fork benchmark** (cf9dfd1c, bc6c680b, 7c53b70c): first native fork
   numbers; all acceptance gates pass; native fork memory scaling tracks
   host COW (+24% @256MiB vs HVF's +121%). `perf_fork_scale` gained argv
   knobs (run-elf cannot inject guest env).
2. **Native vDSO** (3fd3cd83, e69c9597): Darwin reserves host VA
   [63 GiB, 448 GiB) — canonical vvar/vdso bases relocated to +512 GiB with
   `AT_SYSINFO_EHDR` repoint and a vdso-page-only movz rewrite. EL0 counter
   timeline gated by unit test.
3. **Guest CPU time** (03e721ec..31a409be): native provider inside the
   existing `guest_cpu` readers; `proc_pid_rusage` mach-time-unit conversion
   fixed (cross-backend); ITIMER_VIRTUAL/PROF via shared timer-core;
   VmRSS measured over the exact VmSize spans.
4. **Lifecycle** (477fba6b..385e8963): async child-exit watcher (kqueue
   EVFILT_PROC); single-scan adopted-child wait; file-identity futex keys
   (+ unmap retirement); xsig enqueue-before-record; clone3args probe was
   4K-hardcoded (its SIGSEGV was correct 16K behavior).
5. **Residuals** (662fdd60..8a80b70e): host-observed death outranks
   published run-state; native pid-ns placement honored; probeinit shim
   gives the direct-ELF transport the oracle's process topology.
6. **memmap** (b5683bea): geometry-neutral reshape (pagesize_sane; A2
   blocked-grow forced by construction at any page size).
7. **Regression waves** (post-round-7 triage): dnotify = latent missing
   delivery cycle at sigreturn resume, exposed by the vDSO (8ccf81c7);
   EINTR classification for non-set caught signals (9dded86b); fork-safe
   auxiliary-thread locks — ATFORK bundle + AtomicPtr kicker (5afae824);
   shared-futex logical dequeue + self-woken pool + phantom-credit fix
   (73990820, e964894c, 0806a4ae).
8. **MT fork/exec** (e2f298b4..33910df3): dispatch-boundary quiesce
   mirroring the HVF barrier; child sibling-record retirement; cooperative
   exec teardown; ExecReplacedThread + exited-leader park (lost-exec races
   closed); exec-wins CAS vs vfork-suspended leader; linux4k MT shapes are
   typed rejections pending task_c2615fa2. Native now exceeds HVF on
   exec-from-thread and vfork-suspend-exec shapes.
9. **keydeny container policy** (1d7d5d46..054bbb7a): launch-time
   syscall-policy layer at dispatch entry modeling Docker's default seccomp
   (keyring syscalls → EPERM); handlers stay honest-ENOSYS; `--security-opt`
   on run/create/run-elf + serve API; harness mirrors suites'
   `seccomp=unconfined` flags.
10. **sysvsem seed race** (fb706eae): parent's post-fork Booting seed no
    longer clobbers a child's published Blocked state (CAS-from-empty +
    adoption hardening + reader tiebreak); proven by fault injection.
11. **Signal hot path** (2e1ba443): lock-free empty fast path (sticky-raise
    hints) recovered preemptsigstorm's throughput margin shaved by the
    campaign's per-dispatch additions.

Every task went through independent review (spec + quality) with fix waves
for all Critical/Important findings; evidence per task in the git-ignored
`.superpowers/sdd/native16k-task-*-report.md` and `native16k-r*-report.md`.

## Known Follow-Ups (task chips filed)

- task_89f76fff: structural enforcement of signal pending-hint coherence
  (convention-only today; hottest-path hazard class).
- task_c2615fa2: linux4k guarded-fault emulation is not MT-safe (typed
  rejections in place).
- task_3c89e226: wait-family adopted-child gaps (waitid, WNOHANG).
- task_e1f4d3b4: stale bootstrap_host_pid on the off-authority bare
  run-elf path.
- task_b07cef09: amd64 memmap probe oracles hash-stale until fleet re-bless.
- task_a0899be2: parallel-suite fork/port-release test flake (pre-existing,
  reproduced with campaign tests skipped).
- CMP_REQUEUE self_woken under-count (needs identity-carrying credit
  design); doubly-pending set-vs-nonset sigtimedwait divergence (needs
  scoped wait-set-only helper) — both deferred with reviewer-verified
  worse-than-disease rationales, recorded in
  `.superpowers/sdd/native16k-r2-loadcoupled-report.md`.
- Untracked `docs/dynamic-syscall-rewriter.md` (a DSR RFC drafted during
  agent work) awaits a maintainer keep/drop decision.

## Standing Constraints (unchanged)

- Build with `just build` (signed); `lld` never; no `--no-verify`.
- Clean-room: no Linux kernel/glibc/UAPI source.
- Load sensitivity is first-class: classify races vs time-assumptions vs
  measurement; never retry-until-green. Statistical 20-rep batteries are
  insensitive to ~1/950-row campaign rates — lead with mechanism + fault
  injection.
- Never overlap Carrick and Docker phases; scoped `CARRICK_RUN_ID`s +
  `scripts/sudo/kill.sh`.
- Read `.agents/skills/carrick-native-debug/SKILL.md` before native triage.
