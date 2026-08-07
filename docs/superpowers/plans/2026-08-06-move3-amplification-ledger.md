# Move 3 — the Darwin kernel amplification ledger

**Status:** reviewed, execution authority (2026-08-06). This document is the
committed home of the E0 fault-ownership question — which review established is
a **staleness ordering, not a live disagreement** (§2/E0) — whose confirmation
at HEAD is Move 3's first deliverable.
**Scope:** Darwin/aarch64 native backend (`--exec-backend native`, the shipped
default), cold `go build` as the canonical workload.
**Instantiates:** Move 3 of
[`2026-08-05-category-collapse-strategy-design.md`](../specs/2026-08-05-category-collapse-strategy-design.md),
ranked against
[`2026-08-05-category-budgets.md`](../../perf-results/2026-08-05-category-budgets.md).
**Promoted to the front** by that spec's §6 first invalidation condition, which
fired on 2026-08-06 when Move 1 (the live arena) closed negative and was deleted
(`1cb06de6`).

No measurement was taken for this document. Every number is cited from a
committed receipt with its source named; every band is marked *estimated* and
carries the measurement that would confirm it.

---

## 0. The number this plan is ranked against

**The denominator moved on 2026-08-06 and this table uses the new one.**
[`2026-08-06-post-arena-default-refresh.md`](../../perf-results/2026-08-06-post-arena-default-refresh.md)
(`:20`) supersedes the 20.168 s median that category-budgets §2 used: median
Carrick CPU is now **21.391 s (+6.06%)** and the official ratio **10.8586x**
(was 10.1776x), measured at the exact tip that deleted the arena (`1cb06de6` +
`7318f583`).

**Drift flag, per that document's own honesty note:** the +6.06% is *not*
attributed to the delete — the 3-arm smoke proved byte-identical default-arm
guest output across the delete, and the refresh names ~40 commits of tip drift
plus host state (11-day uptime, ambient load ≈2.2) as unseparated terms. Per the
single-variable rule that run cannot decompose them. So the row below is the
current **timing authority**, not a causal statement, and if the +5% persists on
a quieter box it needs its own controlled attribution before anything is priced
against it.

| | share | CPU-s @ 21.391 s |
|---|---:|---:|
| Darwin kernel today (48.4067% midpoint) | 48.4067% | **10.355** |
| — named-syscall | 28.3205% | 6.058 |
| — non-syscall: faults, VM | 20.0862% | 4.297 |
| translated guest | 25.6048% | 5.477 |
| Darwin userspace | 10.0077% | 2.141 |
| other Carrick host code | 8.4276% | 1.803 |
| translation | 6.0116% | 1.286 |
| Kernel budget at the 3x target (Docker-denominated, unchanged) | — | **2.800** |
| **Gap Move 3 must close** | — | **7.555 (−73.0%)** |

The **budget** row is unchanged because it is Docker-denominated
(3 × `cpu_total_s` 2.160 = 6.480 target, kernel residual rounded down to 2.800;
category-budgets §4e). Only the carrick-side numerator moved, so the gap widened
from 6.963 to **7.555 CPU-s**. Every *estimated* band in §2 was derived before
this refresh and is left unscaled — treat them as pre-drift lower bounds.

Source for the shares: category-budgets §2 and §4e. A third, independent confirmation of the
shares landed the same week and is used below wherever a finer split is needed:
`target/perf/attr36/W1OFF-attr.json` (schema `carrick.native-wall-attribution.v1`,
binary `95491fb7…`, source `08531c73`, run `attr36W1OFF74592`), the policy-OFF —
i.e. **shipped-default** — arm of the live-arena attribution round. Its shares:

| category | W1OFF share | samples |
|---|---:|---:|
| darwin-kernel | 48.8161% | 9,030 |
| — kernel-named-syscall | 29.6464% | 5,484 |
| — kernel-non-syscall | 19.1696% | 3,546 |
| translated-guest | 24.6405% | 4,558 |
| darwin-userspace | 10.6985% | 1,979 |
| — `libsystem_platform` (memmove/memset) | 4.6546% | 861 |
| — `libsystem_malloc` | 3.6436% | 674 |
| — `libsystem_kernel` | 1.9083% | 353 |
| other-carrick | 7.2116% | 1,334 |
| translation | 7.0440% | 1,303 |
| process-setup | 1.1785% | 218 |
| gateway / dispatch / unresolved | 0.2487 / 0.1027 / 0.0595% | 46 / 19 / 11 |

`average_cpu_parallelism` 2.2252; `resolved_cpu_coverage` 0.99941; zero
failures. It is a **traced** capture (elapsed 16.659 s against an 8.42 s
untraced anchor), so its shares are citable and its wall is not.

Two more default-lane denominators, from the same round's `C1OFF` counters:
**88,174 guest syscalls** and **1,846,656 gateway exits** on one cold build.
88,174 guest syscalls against 6.058 CPU-s of named-syscall kernel is 68.7 µs per
guest syscall *if every host syscall were attributable to one* — which it plainly
is not. That arithmetic is the whole argument for this instrument: **nobody knows
how the build lane's kernel CPU divides between guest-op service and carrick's
own host traffic**, and the ≥10% mechanism gate cannot find out, because the
answer is a distribution over ~20 guest ops, not a mechanism.

---

## 1. Instrument design

### 1a. What already exists (do not rebuild it)

| existing | what it gives | file |
|---|---|---|
| `carrick trace --profile <kind>` | authenticated capture: the D program is `include_str!`-bundled and its SHA-256 is written into the stream header as `program_sha256`, so an edited program cannot authenticate its own stream | `crates/carrick-cli/src/trace_profile.rs`, `crates/carrick-runtime/src/dtrace_consumer.rs:87-99` |
| `TraceProfileKind` | 6 kinds (`dsr`, `dsr-indirect`, `dsr-fork`, `native-fault`, `native-shape`, `native-wall`), `bundled_script()`, `requires_runtime_profile()`, `parse_protocol()` | `trace_profile.rs:2108-2159` |
| launch qualification | `birth_qualification_sha256` / `terminal_qualification_sha256` hashed into the header; the profile refuses to run until the pre-run probe qualification receipts pass | `trace_profile.rs:333-442`, `BUNDLED_NATIVE_{BIRTH,TERMINAL}_QUALIFY_D` |
| declared bound | `bound_limit_s` as a `/* CARRICK_DSRPROF2_BOUND */` substitution slot + `--profile-bound-seconds`, reported in the completion record so a timeout names the ceiling it hit (raw schema v5→v6) | `08531c73`, and §3 of the 36x attribution |
| guest-op service window | `carrick*:::native-syscall-service-entry` / `-end` USDT, arg1 = guest syscall name | `scripts/dtrace/native-fs-amplification.d:70-84` |
| per-op host-call join | the fs census: `tracked[]` scoping from `$target` + `proc:::create` (never `execname`), filtered + unfiltered joins, `carrick-only` bucket, `section=truncated` → non-zero exit | `scripts/dtrace/native-fs-amplification.d` |
| host **CPU**-ns primitive | `vtimestamp` deltas around `syscall:::entry`/`return` — already the house idiom | `native-whole-cpu-budget.d:50-62`, `native-syscall-cpu-directional.d:52-61`, `exec-window-syscall-latency.d:50-58`, `guest-mmap-shape.d:48-65` |
| fault census | exact `vminfo:::as_fault`/`zfod`/`cow_fault` per process, 1/64 sampled pages, birth-keyed identity, export-contract reconciliation | `scripts/dtrace/native-fault-attribution.d` + `scripts/perf/native_fault_directional.py` |
| typed analyzer pattern | `carrick debug jit-shape-census` → canonical schema `carrick.jit-shape-census.v3`, plus `jit-shape-compare` under a "determinant-locked exact-arithmetic contract" | `crates/carrick-cli/src/debug_jit_shape.rs`, `args.rs:990-1010` |
| owner join | `carrick debug alloc-owner-census` — strict join of allocation-owner fragments to a **complete** NATIVEPERF export, with named failures for a missing/extra process epoch | `crates/carrick-cli/src/debug_alloc_owner.rs` |
| capture driver shape | quiet-host preflight receipt per arm (settled loadavg, `pgrep -x yes == 0`, no stray `carrick:`), `CARRICK_RUN_ID` stamped, `scripts/sudo/kill.sh` after each, refuses to run dirty | the deleted `scripts/perf/live-arena-attribution-capture.sh`, recoverable at `git show 1cb06de6^:scripts/perf/live-arena-attribution-capture.sh` |
| the gate that runs these tests | `cargo test -p carrick-cli --test trace_profile` was added to `just test-integration` on 2026-08-06; `just test`'s `--lib --bins` reaches carrick-cli's in-file `mod tests` | `justfile:132-166`, `:188-218` |

**Design with these, not beside them.** Nothing below invents a second parser,
a second scoping idiom, or a second authority mechanism.

### 1b. What the fs census could not attribute — the four gaps this instrument closes

The Task-4 entry was deliberately shipped before the instrument was designed so
the gaps would be observed rather than guessed
([`2026-08-05-fswalk-amplification-ledger.md`](../../perf-results/2026-08-05-fswalk-amplification-ledger.md)).
They are:

1. **Counts only, no CPU.** The entry's own decision metric is "host-call COUNT,
   not traced elapsed time", and its duration aggregations use `timestamp`, which
   is wall and conflates blocking. The budget is denominated in **CPU-seconds**.
   A ledger that cannot say "this guest op costs X host CPU-ns" cannot be ranked
   against a CPU-second budget at all.
2. **Syscalls only — the non-syscall kernel half is invisible.** 20.09% of all
   CPU / **4.297 CPU-s** is kernel non-syscall (faults, VM). No syscall-entry
   join can see a page fault. A ledger built on syscall spans alone addresses at
   most 58% of the kernel budget.
3. **Mach traps are not syscalls.** The 2026-08-01 audit's central finding is
   that libmalloc's large zone allocates via `mach_vm_allocate`, "**not** `mmap`
   — which is why one traced build shows only 2,172 `mmap` calls against 1.88 M
   zfod, and why every syscall-level instrument aimed at this missed two thirds
   of it." A `syscall:::` join reproduces that blindness exactly.
4. **Not authenticated.** The entry ran via `carrick trace -s <script>`, so the
   script's SHA-256 had to be hand-argued in the doc's Authority section and the
   binary digest had to be separately explained (the instrument landed one commit
   *after* the source commit). Under `--profile`, the digest binding is
   mechanical.

A fifth, from the parallel evidence: **do not rank by kernel stack family.** The
2026-08-03 kernel attribution selected `ml_set_interrupts_enabled_with_debug` at
38.9%/38.5% with a 0.32 pp drift — every statistical gate passed — and exact KDK
+ LLDB attribution then showed the PC is where a deferred sampling interrupt is
*delivered* (`msr DAIFClr, #0x7`), not where the time was spent, with
4,073/4,096 selected samples carrying a single frame so the caller is
unrecoverable. **Guest-op-scoped spans, not kernel stacks.** This is the single
most important negative constraint on the design.

### 1c. The instrument, file by file

**New: `scripts/dtrace/native-amplification.d`** (protocol `AMP1`) — the
generalization of `native-fs-amplification.d`. Header states, per the durable-
artifact rule: (a) what it measures, (b) provider ABI facts qualified live, (c)
that it perturbs and by how much.

Joins, all keyed on the same guest-op service window:

| join | probes | emits |
|---|---|---|
| host syscall count | `syscall:::entry`, unfiltered | `(guest_op, host_call) → count` |
| host syscall **CPU-ns** | `syscall:::entry`/`return`, `vtimestamp` delta | `(guest_op, host_call) → sum, max` |
| **mach trap** count + CPU-ns | `mach_trap:::entry`/`return`, `vtimestamp` | `(guest_op, trap) → count, sum` |
| **fault** count | `vminfo:::as_fault`, `:::zfod`, `:::cow_fault` | `(guest_op, kind) → count` |
| guest-op denominator | `carrick*:::native-syscall-service-entry` | `guest_op → count` |
| independent totals | each of the above, ungrouped | closure check inputs |

Scoping, bounds and failure modes, all inherited verbatim from the fs census
because they are already correct:

- `tracked[]` seeded from `$target`, grown through `proc:::create`, cleared on
  `proc:::exit`, exit on the target's own exit. **Never `execname`** — `carrick
  trace` runs libdtrace in-process inside a `carrick` binary, the trap that made
  54% of an earlier profile the profiler.
- Guest-syscall total of 0 is a **named error** (`wrong-backend`), not an empty
  result: `native-syscall-service-*` never fires under the VMM backend.
- The bound is the declared `/* CARRICK_AMP1_BOUND */` slot (`08531c73`'s
  pattern), defaulted so the unrendered template stays legal; firing it prints
  `section=truncated` and exits non-zero.
- Zero events on **any** required section → named error. A section that prints
  nothing must be distinguishable from a section that printed zero.

Deliberately **not** in the D program: `ustack()`. ~70 self-re-exec'd guest
processes carry independent ASLR slides (fs ledger, "the finding this capture
adds"; audit §"three routes measured dead"), so stacks are corrupted rather than
empty. Call-site attribution is `carrick debug alloc-owner-census`'s job, joined
offline.

**New: `TraceProfileKind::NativeAmplification`** in `trace_profile.rs` —
`as_str()` `"native-amplification"`, `bundled_script()` →
`BUNDLED_NATIVE_AMPLIFICATION_D`, `parse_protocol()`, **`requires_runtime_profile()
== false`**, raw schema
`carrick.amplification.raw.v1`, header carrying `program_sha256` +
`birth_qualification_sha256` + the declared bound. Plus a
`BUNDLED_NATIVE_AMPLIFICATION_D` const in `dtrace_consumer.rs` and the contract
assertions that file already keeps for the other bundled programs (pragma
values, **zero** `copyinstr`, the bound literal present).

> **Corrected 2026-08-06 (implementation).** This line, and Task 1's copy of it,
> originally read "exactly-one `copyinstr(arg0)`" — carried over from
> `native-wall`'s host-catalog contract. It is wrong for this probe:
> `native_syscall_service_entry(number: u64, name: &str)`
> (`crates/carrick-observability/src/probes.rs:2282`) puts the **number** in
> arg0 and the name POINTER in arg1, so `copyinstr(arg0)` would be a wild
> copyin. AMP1 keys on the number and contains no `copyin` at all: that is what
> lets Task 2 resolve guest ops through `CanonicalNr` / the `carrick-abi` table
> with a named error for an unknown op, and it keeps ~88k copyins and a string
> key-space out of the one program whose declared risk is unqualified
> aggregation/dynamic-variable pressure.

> **`requires_runtime_profile()` is FALSE, and this is a correctness point, not
> a convenience.** `native_syscall_service_entry` is an **unconditional** USDT
> (`crates/carrick-observability/src/probes.rs:2282` — an `#[inline(always)]`
> wrapper straight onto `carrick_usdt::native__syscall__service__entry!`,
> opened by `NativeSyscallServiceSpan::open` at
> `crates/carrick-runtime/src/native_darwin.rs:3168`). It fires whether or not
> `CARRICK_DSR_PROFILE` is set, so the ledger needs nothing from the runtime
> profile arm. Requiring it would be an active **measurement confound**: the arm
> is `profiling: std::env::var_os("CARRICK_DSR_PROFILE").is_some()`
> (`crates/carrick-dsr-aarch64/src/translator.rs:2303`) and it does real work —
> the 36x round measured its phase clock at **3.0% of policy-OFF user samples**
> (28.3% policy-ON), i.e. the ledger would be charging carrick host CPU that
> only exists because the ledger asked for it. `TraceProfileKind::NativeFault`
> is already `false` for exactly this probe class
> (`trace_profile.rs:2129-2134`); follow it.

**New: `crates/carrick-cli/src/debug_amplification.rs`** +
`DebugCommand::AmplificationLedger { trace, capture, --output }` — the typed
analyzer. Canonical schema **`carrick.amplification-ledger.v1`**, deterministic
serialization (the `debug_jit_shape.rs` pattern: canonical JSON, byte-identical
on re-run, `parse_census_v1` round-trip). Contents:

```
{ schema, provenance{binary_sha256, git_sha, git_dirty, run_id, host, command},
  authority{program_sha256, raw_schema, bound_limit_s, truncated:false},
  totals{guest_syscalls, host_syscalls, host_syscall_cpu_ns, mach_traps,
         mach_trap_cpu_ns, faults{as_fault, zfod, cow_fault}},
  ledger[ { guest_op, guest_count,
            host_calls, host_call_amplification,          // → 1
            host_cpu_ns, host_cpu_ns_per_guest_op,        // → the budget
            mach_traps, mach_trap_cpu_ns,
            faults{as_fault, zfod, cow_fault},
            dominant_host_call{name, count, cpu_ns} } ],
  carrick_only{ host_calls, host_cpu_ns, faults,
                by_host_call[ {name, count, cpu_ns} ] },  // never a ratio
  closure{ per_op_host_sum == totals.host_syscalls,
           per_op_guest_sum == totals.guest_syscalls, ... },
  budget{ kernel_cpu_s_attributed, kernel_cpu_s_carrick_only,
          share_of_kernel_budget_gap } }
```

Three properties are load-bearing and each is a test:

- **Closure is asserted, not reported.** The fs entry checked its sums by hand in
  prose ("the per-guest-op host totals sum to 52,805… the per-op guest counts sum
  to 24,201"). Here a mismatch is a named `anyhow` failure, so a partial capture
  cannot produce a plausible-looking ledger.
- **`carrick-only` is a first-class bucket with its own decomposition, and can
  never enter an amplification cell.** The fs entry states the rule in prose;
  the type enforces it (no `amplification` field on the `carrick_only` struct).
- **A `--script` capture cannot produce a ledger.** The analyzer requires the
  `AMP1` header's `program_sha256` to equal the bundled template's, and refuses
  otherwise with a named error. This is the whole point of moving the fs census
  under `--profile`.

**New: `DebugCommand::AmplificationCompare { a, b }`** — determinant-locked
exact-arithmetic A/B of two censuses, mirroring `jit-shape-compare`. Refuses to
compare across differing image digest, fixture, guest-op set, or schema. A
lever's before/after is one command, not a hand diff; this is what makes the
ledger *standing* rather than a one-off.

**New: `carrick trace --preflight-quiet-host`** — settle-and-refuse preflight
(loadavg, `pgrep -x yes`, no stray `carrick:` processes) with the receipt written
into the stream header. This is the Rust-first move that shrinks the shell driver
to near nothing: the deleted attr36 driver's `preflight()` was 20 of its ~100
lines and its value was that a dirty host aborted rather than produced a number.

**New (small): `scripts/perf/amplification-capture.sh`** — the remaining
irreducible shell: the arm loop (baseline / candidate), `CARRICK_RUN_ID`
stamping, `scripts/sudo/kill.sh` per arm. Modelled on the deleted attr36 driver,
which the 36x doc keeps precisely because "a capture driver is the reproducible
half of an attribution". Target ≤60 lines; everything it used to do that is
typed now lives in the two Rust commands above.

**Docs:** one row in
[`docs/diagnostics-and-debugging.md`](../../diagnostics-and-debugging.md) and one
in the `carrick-trace` skill.

### 1d. Perturbation budget, declared up front

Four probe families fire on every host syscall, every mach trap and every fault
in a ~70-process tree. The fault probes alone are ~2 M events on this workload
and `native-fault-attribution.d` already declares itself **VERY HIGH**. Expect a
traced run at 2–4x untraced wall. Consequences, written into the D header and
the schema (`totals.wall_is_not_authority: true`):

- **Counts and same-instrument ratios are citable; wall is never.**
- The instrument's own cost must be *identifiable*: `kdebug_trace64` /
  `kdebug_trace_string` land in `carrick-only` (the fs entry found 3,182 of
  them, 6.4% of its run) and the analyzer subtracts them into a named
  `carrick_only.probable_instrument` sub-bucket rather than leaving a reader to
  discover it.
- **A capture with the fault join enabled and one with it disabled are different
  instruments** and their numbers must not be mixed. Make it a header field
  (`joins=syscall,mach,fault`) that `amplification-compare` refuses to cross.

**DTrace drop counters are required closure inputs, not diagnostics.** This is
the one failure mode `section=truncated` does *not* cover: that marker fires
only on the declared tick bound. **DTrace drops silently** — principal buffer,
aggregation, dynamic, dynamic-rinse and dynamic-dirty drops each just make
counts smaller with no in-band signal, which on this instrument would read as a
*lower* amplification and be banked as good news. The risk here is higher than
for any existing profile: **no script in the tree combines
`syscall:::` + `mach_trap:::` + `vminfo:::` + `vtimestamp`**, so the aggregation
key-space and dynamic-variable pressure are unqualified. Therefore:

- the D program declares explicit `aggsize` / `dynvarsize` / `bufsize` headroom
  above the fs census's 32m/64m/16m, and the header records the values it ran
  with (they are a determinant `amplification-compare` refuses to cross);
- `dtrace:::END` emits every drop counter as a named section;
- the analyzer treats **any nonzero drop as a named rejection**, exactly as the
  fault-ownership captures did ("Every DTrace drop counter … was zero" is stated
  as an acceptance condition there, and this instrument adopts it);
- a missing drop section is itself a rejection — absent is not zero.

**A declared join that never armed is the SAME class of silence, and closure
cannot see it either.** `dtrace_consumer` compiles with `DTRACE_C_ZDEFS`, so a
probe description matching nothing is silent rather than an error; the D program
seeds every total `sum(0)` precisely so "printed zero" stays distinguishable
from "printed nothing". Together those make an unarmed join indistinguishable
downstream from an armed one that saw no events — section markers present, rows
absent, a legal zero total — and per-op closure then holds trivially at
`0 == 0` while the ledger loses exactly the mass that join exists to catch.
**Every seeded total must therefore be non-zero**, including both `vtimestamp`
CPU totals (a zero mach-trap CPU total is the D header's own unqualified "does
`vtimestamp` advance across `mach_trap:::`" question answering *no*) and each
fault kind separately, since the fault clause is three independent probe
descriptions. If some workload can legitimately produce zero for one of them,
the remedy is to drop that join from the header's `joins=` set — making the
omission a determinant the comparator refuses to cross — not to soften the check.

**And closure is blind to MISATTRIBUTION**, which is the sharpest remaining edge:
sums are taken across all slots, so moving a row from a guest slot into
`carrick-only` changes nothing that closure checks and simply lowers that guest
op's amplification. That is the shape a dynamic drop produces when a
`service_slot` entry is lost, its symptom is an *improvement*, and the
consumer-side counters are its only detector — see Task 3's required in-band
`AMP1|consumer-drops|…` record.

---

## 2. The entry roster, ranked

Ranked by *estimated* CPU-s against the **7.555 CPU-s** kernel gap (§0). Every
band is an estimate derived from committed measurements of adjacent quantities,
taken **before** the 2026-08-06 denominator refresh; none is a measurement of the
entry itself. That is the honest state — and it is why E0 comes first.

### E0 (prerequisite, not an entry) — the baseline build-lane ledger, and the fault-ownership record it must confirm

The fs ledger measured the **fs-walk** fixture. Every per-op figure in it is
that fixture's. The build lane's amplification at HEAD is **unmeasured**:
AGENTS.md's 19.68 host-opens-per-guest-open is a 2026-07-28 cold-go-build
service-window figure at `564dd281`, flagged stale by AGENTS.md itself, and the
fs entry explicitly declines to restate it ("Restating 19.68 for the go-build at
HEAD is a separate measurement this entry did not make").

#### The fault-ownership record is a STALENESS ORDERING, not a live disagreement

An earlier revision of this plan framed this as a standing contradiction between
the 2026-08-01 audit and AGENTS.md. **That framing was wrong**, and the document
that settles it —
[`2026-08-03-current-native-fault-ownership.md`](../../perf-results/2026-08-03-current-native-fault-ownership.md)
— was uncited. Ordered by date, the record is monotone:

| date | source | claim |
|---|---|---|
| 2026-07-29 | [`2026-07-29-native-cpu-budget-evidence.md`](../../perf-results/2026-07-29-native-cpu-budget-evidence.md) `:123`, `:188` | "Emitted JIT code is NOT the driver: … 2.08% of the zfod faults"; "**the mass is guest anonymous memory plus the fork model**" |
| 2026-08-01 | [`2026-08-01-native-wall-audit-and-fault-cost.md`](../../perf-results/2026-08-01-native-wall-audit-and-fault-cost.md) | bucket histogram vs measured bias, closing to ~99.5%: carrick's own Rust heap ≥128 KiB (libmalloc large zone) **1,254,000 zfod = 66.7% (~20.5 GB)**; guest mmap arena (`zero_backing`) 561,394 = 29.9% |
| 2026-08-03 | `2026-08-03-current-native-fault-ownership.md` | two **source-identical** `native-fault` captures: **host-other share of sampled `zfod` = 63.2115% / 62.7395%** (repeat factors 1.00638 / 1.00146); "ordinary Carrick host allocations, not guest-owned mappings, dominate current-default zero-fill faults" |

So 08-01 and 08-03 **corroborate each other independently** (66.7% by histogram,
63.2%/62.7% by authenticated birth-keyed page census), and AGENTS.md's
guest-dominates bullet traces to the **oldest** of the three. The documentary
record reads: **07-29 superseded by 08-01 + 08-03.** There is nothing to
adjudicate.

**E0's job is therefore CONFIRMATION at HEAD, not adjudication.** It is still
required, because both surviving censuses predate the arena add-and-delete churn
(`0e35a2d3` / `08531c73` era vs the current `1cb06de6`+`7318f583` tip, ~40
commits of drift plus the `8d5b3a19` alias-install fix and the 6E catalog
publication), and §0's +6.06% CPU drift is itself unattributed. A 63%-host-other
finding that no longer reproduces would change E1/E2's ranking completely.

**Explicit E0 deliverables (both required):**

1. `docs/perf-results/2026-08-XX-build-lane-amplification-ledger.md`, same table
   format the fs entry defined, **which produces the real ranking below** —
   including the host-other zfod share at HEAD, stated against the 63.2%/62.7%
   pair so it is a confirmation or a named regression, never a fresh number
   floating free.
2. **Fix AGENTS.md's stale bullet.** The "Do NOT assume carrick's own copies
   cause the fault term — the committed census refutes it … faults are dominated
   by the GUEST's own anonymous memory" bullet cites the 07-29 reading and has
   been superseded twice. Rewrite it to state the current record (host-other
   dominates; JIT first-touch 2.08% and inserted code 1.48% remain true and are
   the *narrow* claim that survives) with the 08-03 citation. This is a
   documentation correction with a measurement behind it, and it is part of E0,
   not a follow-up.

The tooling to do all of this exists and is unwired: the new `AMP1` fault join
gives faults per guest op; `carrick debug alloc-owner-census` gives the
allocation-owner portfolio; `native_fault_directional.py` gives the directional
page census. Nobody has joined all three at HEAD.

### E1 — guest `mmap(MAP_PRIVATE, fd)`: eager full-length materialization

*Estimated* **1.5–3.0 CPU-s** of the kernel gap, plus ~0.9 CPU-s of the
Darwin-userspace budget. Highest ranked, and the mechanism is worse than the
strategy's one-line description.

The strategy names it as "full-length `pread` into fresh anon instead of a host
file-backed mmap". The code (`crates/carrick-runtime/src/dispatch/mem.rs`,
**line numbers re-cited at HEAD**: `PrivateMmapSnapshot` at `:734`,
`snapshot_private_host_file` at `:739`, `snapshot_private_mmap_file` at `:902`,
the `HostFile` arm at `:2508-2525`) is **three** amplifications per guest op, not
one:

1. `let mut bytes = vec![0; length];` — a fresh zeroed heap buffer of the **full
   mapping length**. At ≥128 KiB this is libmalloc's large zone, i.e.
   `mach_vm_allocate` → `length/16 KiB` fresh zfod faults, and it is invisible to
   every `syscall:::`-only instrument (gap 3 in §1b);
2. `libc::pread(host_fd, …, length_usize, offset)` — the kernel copies the whole
   mapping, touching and dirtying every page of (1);
3. the buffer is then copied into the guest arena — a second full-length copy,
   faulting the destination.

On the in-memory VFS arms (`OpenDescription::File` / `SyntheticFile`) there is no
`pread`, but `contents.read_at()` still produces a full-length copy, so the
Vec + copy cost stands.

A native Darwin program expressing the same intent issues **one**
`mmap(host_fd, MAP_PRIVATE|MAP_FIXED)` and demand-pages only the pages the guest
touches, from the unified buffer cache, with no copy at all. Amplification target:
`(1 + 2N/16 KiB faults + 2 N-byte copies)` → **1**.

**Evidence the fix is buildable, not speculative.** The mechanism already exists
in-tree on the exec path: `map_prepared_region_extent`
(`crates/carrick-dsr-aarch64/src/mapped_memory.rs:4601` — **re-cited at HEAD**;
the audit's `:4364` is stale) does
`MAP_PRIVATE|MAP_FIXED` **file** mmaps — 709 per build, ~6 per exec, one per
`PT_LOAD` — against a guest-image zfod count of 11 (audit, "Both levers are
real"). Guest image pages are already file-backed and COW; guest `mmap` is not.
The correction in that same section is load-bearing and must be respected:
`map_prepared_for_plan` (**`:1115` at HEAD**, not the audit's `:1018`) is a
**test-only helper**, the live path is
`map_prepared_region_extent`, and image mapping is **DONE — do not re-implement
it.** This entry is the *general* `mmap` path only.

Supporting shares: `libsystem_platform` 4.6546% (861 samples) and
`libsystem_malloc` 3.6436% (674) of W1OFF — 8.2982% of all CPU ≈ **1.775 CPU-s**
at the refreshed 21.391 s denominator (1.67 at the superseded 20.168 s) in the
copy/allocate userspace pair, which is where (1) and (3) land.

**Confirming measurement:** the E0 capture's `mmap` row — guest `mmap` count,
host CPU-ns, and **fault count inside the mmap service window**. The fs fixture's
`mmap` row (51 guest mmaps → 198 host calls) is far too small to rank from; the
build lane's is unknown. Red-first shape: a `CARRICK_MMAP_FILE_BACKED=0` control
arm (per the opt-out rule) and an `amplification-compare` of the two censuses,
with the `mmap` row's `host_cpu_ns_per_guest_op` and `faults.zfod` as the signal.

**Honest constraint:** the guarantee is immovable. A `MAP_PRIVATE` file mapping
must observe map-time EOF semantics (the `PrivateMmapSnapshot` doc at `:729-733`:
bytes through the last partially backed page snapshotted, EOF remainder
zero-filled, pages wholly beyond published as `BUS_ADRERR`) and carrick's private
mapping is deliberately detached from the vnode so a later external truncate is
not tracked. A host file-backed mapping changes that detachment. The lowering
must preserve the observable contract (LTP `mmap*`, the bus-fault probes) or it
is not eligible — AGENTS.md: correctness is not tradeable for overhead. Note the
usual outcome, though: mapping file-backed *removes* work and *keeps* the
guarantee.

### E2 — carrick's own ≥128 KiB allocation churn → zfod (the cost Move 1 orphaned)

*Estimated* **0.8–2.3 CPU-s**, **overlapping E1** — do not add the two bands.
Combined honest band for E1+E2: **2.0–4.0 CPU-s**.

The strategy's Move-1 table assigned "PC-map/recovery metadata zfod (6.87 GB/build
initialized per-process) ~7.4% projection" to the live arena as "the largest
*identified* chunk of the kernel non-syscall bucket". **The arena is deleted, so
that cost is now unowned** and falls to Move 3 as a memory-intent entry. Its
larger context is the audit's 1,254,000 large-zone zfod (~20.5 GB, 66.7% of all
faults), corroborated by the 08-03 census's 63.2115% / 62.7395% host-other zfod
share (§2/E0). At the audit's own untraced per-fault cost (1.81 µs at
GOMAXPROCS=1, 3.84 µs at 10) that band is 2.27–4.82 CPU-s — which exceeds the
entire non-syscall bucket at the high end, so the low end is the defensible one
and the partition against E1 is required before either is banked.

#### This entry RE-OPENS a committed STOP, deliberately and under named authority

`2026-08-03-current-native-fault-ownership.md` carries an explicit decision on
exactly this territory: **"STOP — the named translation-publication memory
mechanism does not clear the 10% total-CPU gate in either accepted binding"**,
with the opportunity projection at **7.411% / 7.425%** of total cold-build CPU
and the sentence **"No production memory change is authorized."** Task 6 must not
be read as ignoring that decision, so the re-opening is stated here with its
authority:

- The STOP was issued **under the ≥10% single-mechanism policy**, and it names
  that policy as its sole reason for stopping — the measurement itself was
  accepted ("Keep the exact export and Rust censuses"), only the *opportunity
  gate* failed.
- The category-collapse spec **supersedes that policy**. Spec §3 Move 0: the
  ≥10% gate "remains an attribution filter but **stops being a veto**", because
  it "systematically no-carries architectural families that are individually
  <10% while summing to the gap". Category-budgets §5 restates it: a family of
  source-distinct mechanisms individually below 10% but addressable by **one**
  mechanism "is judged as a single candidate against its combined share".
- 7.4% of the refreshed 21.391 s is **~1.58 CPU-s** against a 7.555 CPU-s gap —
  21% of the whole kernel ask from one binding. Under the superseded policy that
  was a no-carry; under the current one it is a ranked candidate.
- **What is unchanged:** the ABBA retention discipline. Re-opening the *ranking*
  does not pre-authorize a production memory change; Task 6 still has to win its
  ABBA, and the 08-03 document's projection was explicitly "deliberately
  favorable", so treat 7.4% as a ceiling on that binding, not a forecast.

**Intent lowering (Go dual-port oracle).** Repeatedly allocating and freeing
≥128 KiB buffers on Darwin returns the pages to the kernel each time and takes a
fresh zfod fault on every re-touch. Go's Darwin port expresses "I want this
memory back but keep the VM entry" as the `MADV_FREE_REUSABLE` / `MADV_FREE_REUSE`
pair and uses **zero** `mprotect` for heap management. The carrick-side
equivalent is buffer reuse / a slab for the repeated large allocations, so the
VM entry and its pages survive between uses.

**Confirming measurement:** `carrick debug alloc-owner-census` (already built,
strict NATIVEPERF join, named failures for epoch mismatch) run at HEAD against
the E0 capture, partitioned against E1's `mmap`-window faults. This entry is
*measurement-first by necessity* — it cannot be ranked until E0 confirms the
host-other zfod share at HEAD (§2/E0).

### E3 — guest decommit intent → `zero_backing` memset instead of `MADV_FREE_REUSABLE`

*Estimated* **0.3–1.0 CPU-s** of the kernel gap (plus userspace memset). The
cleanest AGENTS.md-sanctioned intent lowering left in the tree, and the smallest
diff of the three.

`dispatch/mem.rs:3655` — guest `MADV_DONTNEED` on a writable private mapping
lowers to `cx.memory.zero_backing(address, length)`. Post-`CARRICK_DSR_ZERO_FAST`
(default ON, `=0` hatch — the opt-out rule correctly applied) that is **one
protection lift + one `memset` of the whole range**. Two doc comments record what
it replaced, **both re-cited at HEAD**: the gate
`zero_backing_single_lift_enabled` at `mapped_memory.rs:385-400` carries the
result (host `mprotect` **236,464 → 6,665**, 97.2%, the figure at `:391`), and
`zero_backing` itself at `:3982-4033` carries the mechanism (98% of those calls
at exactly `ZERO_CHUNK`'s 64 KiB, against **8** guest `mprotect` calls, i.e. a
~29,500x amplification that was entirely carrick's own; the 236,464 figure
restated at `:3986`). The same `zero_backing` serves the `MAP_FIXED`/munmap-reuse
scrub.

What remains is still the wrong primitive. After the memset the pages are
**resident and dirty**; the guest's next touch re-dirties them. Darwin's
expression of "decommit, next touch gets a zero page" is
`madvise(MADV_FREE_REUSABLE)`, which returns the pages, keeps the VM entry, and
lets Darwin's zero-fill deliver the guarantee for free on `MADV_FREE_REUSE` /
first touch. AGENTS.md names this exact case as the worked example where the
cheaper primitive **preserves** the guarantee rather than weakening it.

**Confirming measurement:** the E0 capture's `madvise` row — guest `MADV_DONTNEED`
count on the build lane (currently unmeasured; Go's Linux runtime does use
`MADV_DONTNEED`/`MADV_FREE` on its heap, so it should be non-trivial), host CPU-ns
in the window, and the `libsystem_platform` share attributable to the memset.
Red-first: a probe asserting that a `MADV_DONTNEED`'d private anon range reads
back as zero **and** that the host mapping's resident-page count fell —
`mach_vm_region`, since macOS `mincore` is useless (returns success for unmapped
pages).

### E4 — `HostAliasTransactions` gate scope: **re-derive before ranking**

**Do not budget this entry from the 2026-08-01 audit.** The strategy quotes it as
"the `HostAliasTransactions` process-global gate held across `zero_backing`:
9.74 µs vs 6.42 µs per fault and 15x involuntary context switches". That shape is
obsolete twice over:

1. **The mprotect storm inside the gate is gone.** The audit's mechanism was
   `zero_backing`'s per-64 KiB lift/restore pair running under the gate.
   `CARRICK_DSR_ZERO_FAST` cut host `mprotect` 236,464 → 6,665 (E3 above), so the
   gate no longer wraps a ~29,500x amplification loop.
2. **The gate's hold window changed on 2026-08-06.** `8d5b3a19` moved the
   `MapHostAlias` claim → `map_host_alias` → `commit_host_alias_install` sequence
   **inside** `dispatch_native_syscall_inner`'s exclusive arm, under the same
   `memory.write()` guard the dispatch already holds; the deferred run-loop
   install arm was deleted and a `MapHostAlias` escaping dispatch is now a
   fail-closed `RuntimeError`. So a non-Idle Pending/Installing phase always
   belongs to a thread already holding the exclusive guard, and the hold-and-wait
   cycle cannot form.

What the current code actually shows (`dispatch/mod.rs:1939-2010`, `:2467`;
`native_darwin.rs:5756-5773`):

- `begin_dispatch()` is still a **process-global exclusive gate** — one
  `parking_lot::Mutex<HostAliasPhase>` + `Condvar`, waited on until `Idle`;
- it is taken by callers that do **not** mutate mappings: `synthetic_proc_context`
  (i.e. every `/proc/*/maps` read, `mod.rs:5672`), `mmap_fault_is_sigbus`
  (`mem.rs:1299` — on the **fault path**), `mmap_growdown_fault_plan`, `madvise`,
  `remap_file_pages`, and several `fs.rs` / `sysv.rs` sites;
- the 13 syscalls in `native_syscall_mutates_mappings` (196, 197, 214, 215, 216,
  221, 222, 226, 228, 230, 233, 281, 284) now hold the per-process exclusive
  `memory.write()` guard for the **whole** dispatch.

So the entry's question has changed from "the gate is held across `zero_backing`"
to two new ones: **(a) does the exclusive dispatch guard now serialize mapping
syscalls across sibling guest threads for longer than the old phase gate did, and
(b) do the non-mutating gate takers — the fault-path `mmap_fault_is_sigbus` in
particular — need the process-global gate at all?** The arm-B/arm-C topology
sweep (9.74 vs 6.42 µs/fault, 15x involuntary context switches) must be
**re-taken at HEAD** before any band is assigned. Ranked below E1–E3 for that
reason, not because it is small.

### E5 — the build-lane fs term (fs endgame Lever B)

Not top-3, for three stated reasons. (i) The 18.9286x is the **fs-walk fixture's
in-guest window**, not the build's; the build lane's open amplification at HEAD
is unmeasured. (ii) The fs ledger's own next-action is *"ahead of any lever:
bisect the `carrick-only` `fstatat64` movement"* — 32 → 5,802 between 2026-08-02
and `fad9ae0d` on the same filtered join, 11.6% of the tracer-free run, one
bucket moving while all others sit within 0.3%. That reads as a regression, it is
larger than every fs lever, and fixing it may be free. (iii) The ledger predicts
Lever B moves **only** the `carrick-only` bucket and leaves `openat` /
`newfstatat` / `getdents64` amplification flat or one `fstatat64` worse — stated
so a post-Lever-B entry showing those rows flat is read as the expected result.
Lever A (`getattrlistbulk`) and the six-call `fdopendir`/`closedir` directory
preamble (9,360 host syscalls, 18.9% of the fs-walk run) are independent of B and
must be measured separately.

### E6 — `carrick-only` park/wake traffic

Not amplification of any guest op, and it must never enter a per-op ratio — but
it is a first-class ledger row because the count is enormous and the CPU-ns is
exactly what the instrument newly supplies. `syscall-amplification.d`'s recorded
context: on a 90 s go build, 2,902,383 host syscalls of which `psynch_cvwait`
866,678 + `psynch_cvsignal` 861,759 = **60%**.

> **Scoping caveat on that 60%.** `syscall-amplification.d` scopes on
> `execname == "carrick"` (its header argues the case for an already-running,
> ecosystem-wide workload), which is the **opposite idiom** to this instrument's
> `tracked[]`-from-`$target` scoping and the one AGENTS.md records as having
> made 54% of a profile the profiler. Treat the 60% strictly as **count context
> for why this row exists**, never as a figure the ledger inherits: the ledger's
> own `carrick_only.by_host_call` numbers replace it, and the two must not be
> compared.

The on-CPU share bounds it low —
W1OFF puts `psynch_*` at 2.6% of all CPU ≈ **0.56 CPU-s** at the refreshed
denominator — so it is ranked
below E1–E3 on evidence, not dismissed. The 36x round also notes 265.8 s of
off-CPU `runnable_ns` on the OFF arm, almost all idle waiters, so the off-CPU
side is not a hidden reservoir either.

### E7 — the exec chain (listed so it is not re-discovered)

~61–71 guest execs × the measured ~8.5 ms Darwin exec floor ≈ **0.5–0.6 CPU-s**,
mostly kernel and mostly **irreducible**: the spec's §7 honest ceiling says the
only path under it is full guest-pid virtualization, which is explicitly parked.
The 2026-08-02 exec lanes already removed payload hashing and made eligible
`PT_LOAD`s file-backed; one full read of the executable for loader planning
remains. Record the row; do not campaign on it.

### Roster summary

| # | entry | *est.* CPU-s vs the 7.555 gap | confirming measurement |
|---|---|---:|---|
| E0 | baseline build-lane ledger + HEAD confirmation of host-other zfod + the AGENTS.md fix | — (produces the ranking) | the `AMP1` capture itself |
| E1 | guest `mmap(MAP_PRIVATE, fd)` eager materialization | **1.5–3.0** | `mmap` row: host CPU-ns + in-window zfod |
| E2 | carrick ≥128 KiB allocation churn → zfod (Move-1 orphan; re-opens the 08-03 STOP) | **0.8–2.3** (overlaps E1; E1+E2 = 2.0–4.0) | `alloc-owner-census` × fault join |
| E3 | decommit intent → `MADV_FREE_REUSABLE` | **0.3–1.0** | `madvise` row + `mach_vm_region` residency |
| E4 | `HostAliasTransactions` / exclusive dispatch guard scope | unknown — **re-derive** | arm-B/arm-C topology sweep at HEAD |
| E5 | build-lane fs term (Lever B) | unknown; blocked on the `fstatat64` bisect | fs ledger rerun on the build fixture |
| E6 | `carrick-only` park/wake | ~0.56 | `carrick_only.by_host_call` CPU-ns |
| E7 | exec chain | ~0.5, mostly irreducible | already measured |

Bands are pre-drift (derived against the superseded 20.168 s denominator) and are
deliberately **not** rescaled — see §0. Even the optimistic reading (E1+E2 at 4.0,
E3 at 1.0, E6 at 0.56) reaches ~5.6 of **7.555**, and the refresh widened the gap
rather than narrowing it. **Move 3 does not close its own gap from the named
entries alone** — which is precisely why the spec specifies a *standing ledger of
the top ~20 guest operations*, and why E0 is the deliverable that matters most.

---

## 3. Task decomposition (SDD-ready)

Brief-sized units. Every implementation task is red-first; every task names its
gate. Tasks 1–3 are pure instrument work and need no quiet host, so they can run
while another agent holds the box for timed profiling. Tasks 4+ need an
exclusive quiet host and must be serialized against any other perf work.

### Task 1 — `AMP1` D program + profile kind (instrument, part 1)

Add `scripts/dtrace/native-amplification.d` and wire
`TraceProfileKind::NativeAmplification`.

- **Red first:** three fixture-driven cases must fail on the pre-change tree and
  pass after — (a) a raw stream with `guest-syscall-total=0` is rejected with a
  named `wrong-backend` error, not summarized; (b) a stream containing
  `section=truncated` is rejected; (c) a header whose `program_sha256` ≠ the
  bundled template's digest is rejected. Fixtures live beside
  `crates/carrick-cli/tests/fixtures/dsrprof2-valid.raw`.
- **Also asserted:** the `dtrace_consumer.rs` contract tests for the new bundled
  const (pragmas, **zero** `copyinstr` — see the correction in §1c, the guest op
  crosses as a canonical NUMBER — the `/* CARRICK_AMP1_BOUND */` slot present,
  the bound literal legal unrendered).
- **Gate:** `just ci`. Tests must land in `crates/carrick-cli/tests/trace_profile.rs`
  (gated by `just test-integration` since 2026-08-06) or in-file `mod tests`
  (gated by `just test`'s `--bins`). **Do not** put them anywhere else in
  carrick-cli — the house trap is a suite no gate executes.
- **Not in this task:** running the profile. Compile + fixture tests only.

### Task 2 — `carrick debug amplification-ledger` (instrument, part 2)

Typed analyzer + `carrick.amplification-ledger.v1`.

- **Red first** (each must fail on the pre-change tree for the right reason):
  (a) a census whose per-op host sums ≠ the independent total fails with a named
  closure error; (b) `probable_instrument` (`kdebug_trace*`) is subtracted into
  its own sub-bucket and the primary ratios exclude it; (c) a nonzero DTrace drop
  counter — and a *missing* drop section — are each a named rejection (§1d);
  (d) round-trip determinism: serialize → parse → serialize is byte-identical.
- **Type guarantee, not a red test:** a `carrick-only` row cannot carry an
  amplification field because the struct has none. That is true by construction,
  so there is no pre-change tree on which a test of it fails — asserting it as
  "red-first" would be theatre. State it as an invariant of the schema and let
  the compiler hold it.
- **Typed domains:** guest-op names are not bare strings across the boundary —
  reuse `CanonicalNr` / the `carrick-abi` syscall table to resolve names, so a
  guest op that is not in the table is a named error rather than a silent row.
- **Gate:** `just ci` + `just lint-domains`.

### Task 3 — `amplification-compare` + `--preflight-quiet-host` (instrument, part 3)

- **Red first:** comparing two censuses that differ in image digest, fixture,
  `joins=` set, `program_sha256`, the declared buffer sizes, or schema fails with
  a named determinant error; comparing two identical censuses reports exact
  zeros. `program_sha256` is on that list because Task 2 deliberately moved the
  bundled-digest check OUT of the ledger parser: folding it in would make every
  previously published ledger unparseable the moment `native-amplification.d`
  is edited (including by the in-band record below), destroying the archive.
  A ledger always names the program that produced it; **refusing to cross a
  version is the comparator's job, not the parser's.**
- **REQUIRED, default-on: an in-band `AMP1|consumer-drops|…` record.** Task 2's
  review established that this is not a nicety. Closure sums across all slots,
  so it is blind to MISATTRIBUTION: moving a `(guest_op, host_call)` row from a
  guest slot into `carrick-only` leaves every sum and every closure pair
  unchanged and simply lowers that guest op's amplification. A reviewer
  constructed exactly that from the committed fixture — `openat` fell from 10/4
  to 7/4, exit 0, ledger published. It is also precisely the shape a libdtrace
  **dynamic drop** produces when the `service_slot[pid, tid]` entry is lost.
  The consumer-side drop counters are therefore the SOLE detector for a
  corruption whose symptom is an *improvement*, they are not readable from D
  (D header fact 10), and today they exist only in the live `DTraceRunReport`,
  so an archived raw from a FAILED capture can launder a lower amplification
  past every offline check. Task 3 must have `carrick trace` write those
  counters into the stream as an `AMP1|consumer-drops|…` record after libdtrace
  finishes, with the reader requiring the record (absent is not zero) and
  refusing any nonzero counter — **default-on, `=0` hatch only for bisection**,
  per the opt-out rule. Until it lands, "the capture command exited zero" is an
  unrecorded part of every ledger's provenance.
- `carrick trace --preflight-quiet-host` writes its receipt into the header and
  exits non-zero on a dirty host; a fixture test asserts the refusal path.
- Write the ≤60-line `scripts/perf/amplification-capture.sh` arm driver.
- **Gate:** `just ci`. Docs rows in `diagnostics-and-debugging.md` + the
  `carrick-trace` skill for **both** new commands — `amplification-ledger`
  (Task 2) and `amplification-compare` — not just the comparator.

### Task 4 — E0: the baseline build-lane ledger (**needs an exclusive quiet host**)

First live use of the instrument. Cold `go build` fixture, byte-identical to
`scripts/perf/workload-spread.sh`'s and to the 36x round's `series-b`, same
image digest.

- Capture with all three joins; then a syscall-only capture for the ratio the fs
  entry can be compared against.
- Run `carrick debug alloc-owner-census` on the same run and join.
- **Deliverable 1:** `docs/perf-results/2026-08-XX-build-lane-amplification-ledger.md`
  in the fs entry's table format, including the **host-other zfod share at HEAD
  stated against the 08-03 pair (63.2115% / 62.7395%)** — a confirmation or a
  named regression, never a free-floating new number.
- **Deliverable 2:** the **AGENTS.md correction** (§2/E0) — rewrite the stale
  "faults are dominated by the GUEST's own anonymous memory" bullet, which cites
  the superseded 2026-07-29 reading, to state the 08-01 + 08-03 record. Part of
  this task, not a follow-up.
- **Gate:** completeness — no `section=truncated`, **every DTrace drop counter
  zero and the drop section present** (§1d), closure exact, **every declared
  join's totals non-zero** (§1d: an unarmed join is silent under `ZDEFS` and
  closes at `0 == 0`), `carrick-only` decomposed, instrument calls named and
  excluded. Because the in-band consumer-drop record is Task 3's, the capture
  command's **zero exit status** is itself a gate condition here: a raw file left
  behind by a failed capture passes every offline check.
  Single capture is acceptable for **counts** on a deterministic fixture (the fs
  entry's precedent, reproducing a prior census to within 2 guest calls);
  **CPU-ns needs n ≥ 3** and its variance reported, because unlike counts it is
  load- and core-class-sensitive (4 P + 6 E cores — a concurrency sweep is never
  a clean variable).
- **This task re-ranks E1–E7.** Everything below is provisional on it.

### Task 5 — E1 red-first probe, then the file-backed lowering

- **Red first, and this one is a conformance probe, not a unit test:** a probe
  that maps a file `MAP_PRIVATE`, asserts map-time EOF semantics (zero tail,
  `BUS_ADRERR` beyond the last partially backed page) and the detached-truncate
  behaviour, verified DIFF-free against the Docker oracle *before* the lowering
  lands. A probe that passes immediately proves nothing.
- Lower eligible guest `mmap(MAP_PRIVATE, host_fd)` to a host
  `MAP_PRIVATE|MAP_FIXED` file mmap on the identity/aperture backend, reusing
  `map_prepared_region_extent`'s existing mechanism. Eligibility is narrow and
  explicit (`OpenDescription::HostFile`, offset/length page-aligned, no
  shared-aperture conflict); everything else keeps the snapshot path.
- **Default ON**, hatch `CARRICK_MMAP_FILE_BACKED=0` (opt-out rule).
- **Gates, in order:** the probe green vs Docker → `just ci` → `just
  conformance-probes` **as a DELTA gate, not a pass/fail gate** (see below) →
  `amplification-compare` on the `mmap` row → cold-build
  ABBA. Retained only on an ABBA win; if it wins its mechanism and loses its
  ABBA, that is the spec's §6 second invalidation condition and the coupling is
  in the memory system — stop and report, do not park it behind a flag.

> **`just conformance-probes` is RED at HEAD and its failure set is not
> deterministic**, so "gate on green" would be unsatisfiable and "gate on the
> set" would produce false regressions.
> [`2026-08-06-native-live-arena-compiler-qualification.md`](../../perf-results/2026-08-06-native-live-arena-compiler-qualification.md)
> `:243-256` records it: one-worker (authoritative) runs give `arm64:musl:`
> `{accounting, aliassize, clone3args, mmapcluster, recursionguard}` at
> `53f5ee60`, the same five **plus `reparenttoinit`** at `b5d0ff2b`, and an
> **eight-worker** run of the tip gave a different set again (`forksigwalk`,
> `msgoverflow`, `pidnsinitreap`). Three of the stable five are already recorded
> as pre-existing native-lane gaps, and the gate is not part of `just ci`.
> **Amended gate:** pin the baseline failure set with a **one-worker** run on the
> pre-change signed binary, re-run one-worker on the candidate, and gate on the
> **delta** — any probe that is newly red is a regression; any probe already in
> the pinned set is not. Never sample at eight workers for this comparison, and
> never treat a single-sample set difference as evidence.

### Task 6 — E2: partition the large-zone fault mass, then reuse

Sequenced strictly after Task 4's confirmation.

- **Open the brief by restating the re-opened STOP** (§2/E2): the 08-03 document
  says "No production memory change is authorized" *under the ≥10% policy*; the
  category-collapse spec §3 Move 0 and category-budgets §5 supersede that policy
  and make this a ranked candidate. Cite both. A reviewer must be able to see the
  decision was re-opened deliberately, not overlooked.
- If HEAD confirms carrick's own large-zone heap dominates (the expected result,
  63.2%/62.7% at 08-03): identify the top allocation
  owners from `alloc-owner-census`, and apply reuse / `MADV_FREE_REUSABLE`+`REUSE`
  to the repeated ≥128 KiB allocations, one owner at a time, each with its own
  ABBA.
- If HEAD instead shows guest anonymous memory dominating — i.e. the 08-01/08-03
  finding does **not** reproduce after the arena churn — that is a named
  regression in the record, not a return to the 07-29 reading. Report it as such,
  re-scope the entry to "make each guest page cheaper on Darwin" against E3, and
  do not pursue an allocation fix. **Say which, from the measurement.**
- **Gates:** `just ci`; ledger `faults.zfod` movement; cold-build ABBA. The
  ABBA discipline is explicitly *not* relaxed by the re-opening.

### Task 7 — E3: decommit intent lowering

- **Red first:** a probe asserting `MADV_DONTNEED` on a private anon range reads
  back zero **and** that host residency fell, read via `mach_vm_region` (macOS
  `mincore` is useless — it reports success for unmapped and gap pages). Red
  against the current memset path on the residency assertion.
- Lower `MADV_DONTNEED` (and the `MAP_FIXED`/munmap-reuse scrub where the range
  is private anon and non-executable) to `madvise(MADV_FREE_REUSABLE)`, keeping
  the multi-region and may-execute fallbacks `zero_backing` already carves out.
- **Default ON**, hatch `CARRICK_DECOMMIT_REUSABLE=0`.
- **Gates:** probe green → `just ci` → LTP `madvise0*` cases vs the oracle →
  ledger `madvise` row → cold-build ABBA.

### Task 8 (parallel, cheap) — E4 re-derivation

Re-take the arm-B (10 threads × 1 process) vs arm-C (10 processes × 1 thread)
topology sweep at HEAD, controlling core class, and re-derive the
`HostAliasTransactions` entry's present shape. Report only; no code change is
authorized from it until the numbers exist. Note the confound the audit itself
records: `go build` takes `-p` from `GOMAXPROCS`, so a GOMAXPROCS sweep changes
threads, processes and core class at once and is not a clean variable.

---

## 4. What would invalidate this plan

- **Task 4 shows `carrick-only` dominates the build lane's host CPU** (as the
  60%-psynch context and the fs entry's 16.7% both hint). Then Move 3 is not a
  per-guest-op amplification program at all — it is a carrick concurrency-structure
  program, and E1–E3 are minor. Re-scope rather than proceed.
- **Task 4 shows the kernel CPU is concentrated in one host call with a low
  per-guest-op multiple.** Then the ledger's "drive each toward 1" framing is
  wrong for this lane and the lever is per-call cost, not amplification.
- **E1 wins its mechanism and loses its ABBA.** Spec §6, second condition: the
  coupling is in the memory system. Stop the entry line and report.
- **The 08-01/08-03 host-other zfod finding does not reproduce at HEAD.** Then
  E2 collapses into E3 and the roster's top band drops by roughly 1 CPU-s — and
  the non-reproduction is itself a named regression to attribute against the
  ~40 commits of post-arena drift, not a quiet re-ranking.
- **§0's +6.06% CPU drift turns out to be a real regression rather than host
  state.** Then the gap is not 7.555 and the first work is attribution, not
  amplification.

## 5. Explicit non-goals

- No kernel-stack-family ranking, ever (§1b, fifth gap).
- No second parser, second scoping idiom, or second authority mechanism: the
  ledger extends `carrick trace` / `carrick debug`, per the Rust-first rule.
- No `--script`-authenticated ledger artifact. A `-s` capture stays diagnostic.
