# Qualifying the live-arena compiler slice: gates green, and an intermittent policy-ON deadlock that blocks the retention gate

**Date:** 2026-08-06. **Lane:** container-lifetime live translation arena,
compiler-only slice (`CARRICK_DSR_LIVE_ARENA=compiler`), Darwin/arm64 native
backend. **Plan:** `docs/superpowers/plans/2026-08-05-native-live-translation-arena.md`
§ Task 9.

**Headline:** every static and policy-OFF gate is green, the Task-8
instruments work on first arming, and the live arena demonstrably shares
translations at scale — **but the policy-ON reference workload deadlocks
intermittently (4 of 7 determinate runs), on this tip AND on Task 7's tip.**
The 10% retention ABBA must not run until that is fixed: half its samples
would be hangs.

---

## 1. Provenance

| what | value |
|---|---|
| source commit | `b5d0ff2b7d01f5f8d4c109e6d5beb54bccf20bba` (clean tree) |
| binary | `target/release/carrick` SHA-256 `833d6db2669ed1abfad384858a1bb00d539fc599ec3ec55cd82e1d90fe519b6a` |
| build | `scripts/build-signed.sh`; reproduced byte-identically across three separate builds of the same commit |
| entitlement | `com.apple.security.hypervisor` present |
| USDT | `__TEXT,__dof_carrick` present, `size 0x9b1f` |
| pre-change comparison binary | `d0a65e21c48107e3404f011af6db69716f9d139ed109f025e3b40b5ebe7c01f6` (`9083c1d3`, Task 7 tip) |
| pre-campaign comparison binary | `47f50141f5645006eaa9dcc2da511b725648e95ac38037358869408d2db913f2` (`53f5ee60`) |
| workload image | `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b` |
| host | macOS 27.0, arm64, 4 performance + 6 efficiency cores, AC power |
| D program | `scripts/dtrace/dsr-live-arena.d` SHA-256 `1c2d6758fd4d457d20ee68d4c2927fdc04c1ce2cb0da4505591c5bdeeecc27a5`, bound into the capture header |

Raw receipts (uncommitted): `target/perf/task9/`.

---

## 2. Gate results

| gate | verdict | receipt |
|---|---|---|
| signed build + DOF + entitlement + digest | **GREEN** | `G1-binary-provenance.log` |
| focused correctness matrix (13 plan categories) | **GREEN**, 0 failures | `G2-matrix.log` |
| live-arena module suites (`carrick-dsr-aarch64` 108, `carrick-native-darwin` 37, `carrick-runtime` 10) | **GREEN** | `G2-matrix.log` |
| live-arena trace-profile authority (4 cases) | **GREEN** | `G2-matrix.log` tail |
| `RUST_TEST_THREADS=1 just ci` | **GREEN**, exit 0 | `G3-just-ci-serialized.log` |
| three-arm signed smoke (unset / `=0` / `=compiler`, ×3) | **GREEN**, 9/9 exit 0, byte-identical `3d6fb595…7e53` | `G4-smoke-three-arm.log` |
| `conformance-native smoke`, serialized, quiet host | **GREEN**, 23/23 MATCH | `G4-conformance-native-smoke-serial.log` |
| LLDB live + core cross-check | **GREEN**, identical record | `G5b-*.log` |
| authenticated `dsr-live-arena` DTrace capture | **GREEN** on first arming | `arena-summary.jsonl` |
| broad `native-wall` capture, policy ON | **NOT OBTAINABLE** — see §6 | `G6-wall-capture.log` |
| policy-ON reference workload completes | **RED, intermittent** | §4 |

Two gates that are red for reasons predating this campaign are recorded in §7
rather than counted above.

---

## 3. The live arena works: first arming of the `dsr-live-arena` profile

`carrick trace --profile dsr-live-arena` on a policy-ON cold `go build`
(run id `task9arena40408`). The capture ended on the D program's own
`tick-300s` bound (`bounded=true`), the designed shape for a workload longer
than the bound; the parser accepted it — the zero-event rejection did not
fire, and the stream carries the authenticated
`DSRLIVE1|header|profile=dsr-live-arena|program_sha256=1c2d6758…` line.

| outcome | count |
|---|---|
| kind 13 — READY hit (another publisher's record served) | **509,776** |
| kind 14 — winner publication (this process published the block) | **64,055** |
| kind 16 — named private fallback | **8,417** |
| kind 15 — CAS loss | 0 |
| kind 17 — validation refusal | 0 |
| kind 18 — stale-abort recovery | 0 |
| revoked chunks | 0 |
| `translation-attempts` denominator (initial misses) | 138,064 |
| distinct pids producing live outcomes / attempting translations | 31 / 56 |

Read carefully: **98.7% of live-arena consultations were answered from a
record some process had already published** (509,776 of 509,776 + 8,417), and
each published block was consumed about eight times (509,776 / 64,055). That
is the mechanism the design exists for, observed cross-process at scale, with
zero validation refusals and zero revocations on this workload. READY hits
exceed the `translation-attempts` denominator because a consultation can be
served repeatedly per lookup (the repeat-lookup contract Task 6D disclosed);
the denominator counts initial misses only, so the two are not a simple share.

**This is mechanism evidence, not a performance claim.** One traced run;
tracing perturbs.

---

## 4. BLOCKING: the policy-ON workload deadlocks intermittently

### 4.1 What was observed

The reference workload (cold `go build` of a one-line package, native backend)
hangs with the guest tree alive but making no progress — the documented wedge
signature, elapsed ≫ CPU:

```
38477 S etime=08:26 cpu=0:00.59  carrick:…: /bin/sh -c
38480 S etime=08:25 cpu=0:00.87  carrick:…: /bin/sh -c
38483 S etime=08:25 cpu=0:02.37  carrick:…: go
38530 S etime=08:18 cpu=0:00.10  carrick:…: compile     <- 0.10 s CPU in 8 minutes
```

### 4.2 Frequency, and it is NOT this task's changes

| binary | policy | determinate runs | wedged |
|---|---|---|---|
| `b5d0ff2b` (Task 9 tip) | `compiler` | 4 | **3** |
| `9083c1d3` (Task 7 tip) | `compiler` | 3 | **1** |
| `b5d0ff2b` | off (shipped default) | 1 + the whole 23-suite conformance smoke + 9-run smoke | **0** |

Successful policy-ON runs land at 379–382 s wall on both binaries, so a wedge
is unambiguous against a ~6-minute expectation. Task 7's report recorded
"BUILD_OK ×3" — with a per-run wedge probability in this range, three clean
runs is roughly a 1-in-3 outcome, so that receipt is consistent with the defect
already being present and simply not sampled.

The defect is therefore **in landed campaign work, but not in Task 8's
instrumentation**, and it does not touch the shipped default: policy-OFF
completed every time it was asked to today, including 23/23 conformance suites
and 278 CPython `subprocess` cases.

### 4.3 Topology (identical across three independent wedges)

From `lldb -p <compile-pid> -o "bt all"` — a real attach on a wedged process,
not `sample`:

- **thread #1** (`compile` main): parked acquiring the EXCLUSIVE
  `memory.write()` guard at `crates/carrick-runtime/src/native_darwin.rs:4977`,
  inside a **claimed host-alias transaction** (`transaction.claim()` returned
  `Some(install)`, so this thread already owns the alias phase);
- **thread #5**: parked in
  `HostAliasTransactions::begin_dispatch`,
  `crates/carrick-runtime/src/dispatch/mod.rs:1957` — `self.idle.wait(&mut phase)`,
  waiting for the alias phase to return to `Idle`, reached from a guest `mmap`
  (`dispatch/mem.rs:1711`);
- **threads #3/#4**: parked in `complete_dsr_syscall`
  (`native_darwin.rs:5097`) and `prepare_dsr_entry` (`native_darwin.rs:3861`);
- the parent `go` process: parked in
  `carrick_thread::thread::FutexTable::wait_prepared_with_token` via
  `wait_native_futex`, i.e. waiting on the compiler child that never finishes.

That is a lock-order inversion between the host-alias phase machine and the
mapped-memory `RwLock`: one thread holds the alias phase and wants the memory
write guard, while another holds memory access and wants the phase idle.
`parking_lot`'s writer-preferring `RwLock` then parks the remaining readers
behind the pending writer, which is why all four threads are asleep.

Whether the live arena introduces the cycle or merely changes the timing
enough to expose a latent one is **not settled here** and must not be guessed:
the policy-OFF path takes the same `begin_dispatch` route without wedging in
any run today. Establishing that is the first step of the fix, and it wants
the pre-change binaries listed in §1 plus a reduced reproducer, not this
document's inference.

### 4.4 A methodology note, recorded so it is not paid for twice

The first cross-check harness POLLED for a candidate by attaching lldb to every
guest process of the run. Each attach `SIGSTOP`s the whole target, and one
sibling was left in state `T` for ten minutes, which wedged that run
independently of the defect above. `SIGCONT` resumed it. The corrected harness
never probes with an attach: it waits for a `compile` guest **by proctitle**
and attaches exactly twice, back to back, to that one process — and the tree
was still healthy (`stat` = `S`, no `T`) immediately after both attaches. The
defect in §4.1–4.3 was subsequently reproduced with **no debugger involved at
all**, which is what rules the harness out as its cause.

---

## 5. LLDB live + core cross-check (Task 8's export, first real use)

One policy-ON `compile` child, pid 41211. Attach 1 dumped the export; attach 2
resolved a cache PC and took the core from the **same stopped state**, so the
live answer and the core answer describe one instant.

| | live attach | core (266,969,088 bytes) |
|---|---|---|
| RX payload | `0x10eeb8000 .. 0x112eb8000` | `0x10eeb8000 .. 0x112eb8000` |
| READY records | total **40,035**, ring of 512 | total **40,035**, ring of 512 |
| revoked chunks | 0 | 0 |
| resolve `0x11070bfd0` | `block guest_start=0x6ca55c entry=0x11070bfd0 offset=0x0` | `block guest_start=0x6ca55c entry=0x11070bfd0 offset=0x0` |

Both views also emit the same honest caveat that an exact mid-block guest PC
lives in the arena's COLD recovery metadata, which the export deliberately does
not copy. `carrick xlat-live-arena` validated magic, version and both record
strides before decoding in each case.

---

## 6. The broad wall capture: refused, with the reason

`carrick trace --profile native-wall` on the same policy-ON workload **fails**:

```
Error: trace failed: DTrace post-stop callback failed: validate authoritative
DSRPROF2 stream …: gating DSRPROF2 capture timed out
```

`scripts/dtrace/native-wall.d` bounds itself at `tick-180s`, and the profile
*gates* on the target exiting naturally within that bound
(`crates/carrick-cli/src/trace_profile.rs:2035`). A policy-ON build needs
~380 s, so the instrument cannot describe the arm it is most needed for. This
is a tooling gap for Task 10 to close (the bound is a literal in the D program,
and raising it changes every other capture's cost, so it deserves a deliberate
decision rather than an ad-hoc edit here).

What the same instrument does say about the **policy-OFF** baseline
(`walloff-summary.jsonl`, complete=true, bounded=false, target exited
naturally, 44,069 metric rows, workload 30.8 s traced vs 15.6 s untraced — the
trace roughly doubles it):

| bucket | samples |
|---|---|
| wall samples | 6,202 |
| wall state: **runnable-descheduled** | **5,816 (93.8%)** |
| wall state: on-cpu | 386 (6.2%) |
| kernel PCs in a named syscall | 6,771 |
| kernel PCs outside a syscall | 5,396 |
| top kernel syscalls | `kevent` 2,039 · `fork` 1,429 · `psynch_cvwait` 904 · `poll` 734 · `openat` 562 |

Even with the arena off, the traced build is overwhelmingly **runnable and
waiting for a core**, not executing. Same-instrument comparison only.

### 6.1 The policy-ON multiple, as mechanism evidence

Untraced, same guest script, same binary, same box, single runs:

| arm | wall | in-guest workload window |
|---|---|---|
| policy OFF | 20 s | 15.61 s |
| policy ON | 382 s | 380.89 s |

≈ **24x** on the workload window. This SUGGESTS the cost is concentrated in
guest-visible work rather than container setup; it is one run per arm with no
controlled variable, so it is not a measurement. It sits alongside Task 7's
~38x figure, which used a different harness; neither is a perf claim.

---

## 7. Two pre-existing red gates, attributed

**`conformance-probes` is red at both binaries.** One-worker (authoritative)
runs give `arm64:musl:` `{accounting, aliassize, clone3args, mmapcluster,
recursionguard}` at `53f5ee60` and the same five **plus `reparenttoinit`** at
`b5d0ff2b`; an eight-worker run of the tip gave a different set again
(`forksigwalk`, `msgoverflow`, `pidnsinitreap` instead of `reparenttoinit`).
Three of the stable five are already recorded as pre-existing native-lane gaps
in `docs/perf-results/2026-08-03-persistent-store-default-confirmation.md`. The
set is not deterministic across samples, so the single-sample `reparenttoinit`
delta is not evidence of a regression; the gate as a whole predates the
campaign and is not part of `just ci`.

**`conformance-native smoke` at its default eight workers** produced two gating
verdicts — `ltp-epoll_create01` REGRESSION and a `go-build` TIMEOUT at 296x —
that both vanish on a quiet serialized re-run (`carrick[2/2] oracle[2/2]`;
`go-build` MATCH). That is the load-coupling the recipe's own comment warns
about, not a regression.

---

## 8. What this means for Task 10

The retention ABBA cannot run. Its arm B is exactly the configuration that
hangs, so at the observed rate roughly half of its eight samples would be
wedges rather than measurements, and no confidence interval computed over that
is meaningful. The order is: settle §4.3 (does the live arena introduce the
lock cycle or expose it), fix it, re-qualify with these same gates, and only
then measure.

---

## 9. ADDENDUM (2026-08-06, post-fix): host contamination — which of this doc's numbers are loaded, and what supersedes them

Discovered after this document was written: **8 orphaned `yes` load
generators** — leaked by this task's own fd-leak-fix load experiment (§ the
carrick-host interference sweep), cleanup never ran, reparented to PID 1 —
saturated 8 cores for **~4h49m**, covering every timed run and wedge
reproduction above. They were found and killed only after the deadlock-fix
task's first regression gauntlet was already running.

Contaminated (measured under the leaked load, do not quote):

- **All policy-ON wall times** here (the 379–382 s "healthy" band, the ~24x
  workload-window attribution in §6, and by extension Task 7's ~38x).
- **The wedge rates** (3/4 at this tip, 1/3 at Task 7's tip, "4 of 7" in the
  headline): these are LOADED rates. The only pre-contamination quiet
  observations are Task 7's 0/3; **the quiet-host wedge rate of the pre-fix
  binary is UNKNOWN.**
- The §7 eight-worker `conformance-native smoke` load artifacts (the
  REGRESSION/TIMEOUT pair that vanished on serialized re-run) — the "load"
  in that load-coupling included the leak.

Still valid:

- **The deadlock topology and root cause.** The three lldb wedge attaches
  (§4.3) are structural evidence — load widens race windows, it does not
  fabricate hold-and-wait cycles. The cycle was root-caused and fixed in
  `8d5b3a19` (`fix(native): install host aliases under the dispatch memory
  guard`; abort-semantics follow-up `bcd2062e`).
- The static gates, the policy-OFF conformance results, and the arena's
  READY/private sharing counts (§5) — counter ratios, not timings.

Superseded by (deadlock-fix task, fixed binary `00e9e493…24d943`, receipts
`target/perf/task9/series-{a,b}.log`):

- **Series A (power):** 8/8 policy-ON cold go builds clean under a
  DELIBERATE 8x `yes` load — the condition reproducing this doc's wedge
  environment, where the pre-fix binary wedged 3 of 4. Walls 377–414 s.
- **Series B (first uncontaminated policy-ON numbers):** quiet host,
  per-run settled preflight receipts. Policy-ON 335–442 s wall (median
  ~365 s), policy-OFF 9–11 s — **~36x**, single-run-class mechanism
  evidence. Note the loaded→quiet delta: ON barely moves (~394 s loaded
  mean vs ~370 s quiet mean, ~6–10%) while OFF halves (20 s loaded → 10 s
  quiet); the old loaded-vs-loaded ~19–24x reading UNDERSTATED the
  overhead, and policy-ON's insensitivity to CPU contention is the
  signature of lock-serialized execution (see the deadlock task report §7,
  `.superpowers/sdd/2026-08-05-native-live-translation-arena-task6/task-deadlock-report.md`).

Task 10 consequence: the retention ABBA is unblocked by the fix, but its
baseline expectations must come from Series B, not from any number above.
