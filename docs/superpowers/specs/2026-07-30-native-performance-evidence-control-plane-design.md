# Darwin native performance evidence control plane

- **Date:** 2026-07-30
- **Status:** conceptual and written design approved 2026-07-30
- **Lane:** Darwin/AArch64 native DSR only
- **Controller:** `handoff.md` and
  `docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`
- **Primary workload:** cold-`GOCACHE` Go 1.24 hello-world compile and execute
  from `scripts/perf/native_go_build.py`

## 1. Purpose

The active campaign must reduce native-backend CPU, not merely move an
internal counter. Its official total-CPU destination is a paired candidate /
`0686248a` ratio at or below **0.70** on the primary workload. The result must
also contain material improvements in both:

- the translation side: private and shared translated execution plus
  translation-build, translation-publication, gateway-prepare, and
  gateway-resolve host work; and
- Darwin non-syscall kernel work.

The current evidence cannot safely choose the next implementation:

- the durable ABBA wrappers named in the handoff are absent;
- `native-wall` announces only the private JIT range, so shared unit code is
  charged to an incorrect or unresolved owner;
- aggregate `vminfo:::zfod` counts have no qualified host-page ownership or
  repeat factor; and
- the largest remaining translation and kernel hypotheses are therefore both
  plausible but not discriminated.

This design supplies that missing evidence control plane. It does not itself
claim the 0.70 campaign goal. Once the tools produce accepted current-tip
evidence, the larger of the translation-locality and fault-owner ceilings
becomes a separately designed and measured implementation slice.

## 2. Fixed decisions

1. Untraced paired CPU is the retention authority. DTrace establishes
   mechanism and attribution; it never supplies an official speedup.
2. CPU means the `RUSAGE_CHILDREN` delta currently emitted by
   `native_go_build.run_sample`. It is a stable paired metric and a known floor,
   not a claim of exhaustive process-tree CPU.
3. Full-process wall time and the in-guest workload window remain secondary
   diagnostics. They may reject a pathological candidate, but cannot rescue a
   CPU regression.
4. The campaign keeps two baselines:
   - `H0`: the frozen `0686248a` binary used only for the official total-CPU
     destination;
   - `I0`: the first accepted untraced and traced baseline after this
     instrumentation lands, with every optimization hypothesis in its control
     state.
5. The control-plane binary must be neutral against `H0`: its paired total-CPU
   estimate may not exceed 1.00 and its one-sided 95% upper bound may not exceed
   1.02. Failure sends the instrumentation itself back for redesign.
6. A final component improvement is material when its CPU-seconds estimate is
   at least 10% below `I0` and the decrease is larger than twice the larger of
   the two-run within-state dispersions. This applies independently to the
   translation-side and non-syscall-kernel buckets.
7. A component estimate is:

   `untraced median total CPU × accepted native-wall sample share`

   It is reported as an estimate, never mixed with the official paired total.
   The translation-side definition deliberately includes constant guest work;
   a reduction in this conservative inclusive bucket is stronger than a
   reduction in an inferred overhead-only remainder.
   Its share is exactly the sum of `private-translated`,
   `shared-translated`, `translation-build`, `translation-publication`,
   `gateway-prepare`, and `gateway-resolve`. Only exact Carrick-resident leaf
   symbols count in the four host-work categories. A sampled Darwin callee
   such as `memmove` remains `darwin-userspace` even when its caller performed
   translation publication, so this is a deliberately conservative
   translation-side estimate. The kernel component is exactly
   `kernel-non-syscall`.

   For a state with two accepted profiles, `E1` and `E2` are the two component
   estimates and dispersion is `abs(E1 - E2) / mean(E1, E2)`. A final
   component passes only when `mean(Efinal) / mean(EI0) <= 0.90` and the
   fractional decrease is greater than
   `2 × max(dispersion_final, dispersion_I0)`.
8. `native-wall` defines non-syscall kernel work by sampling kernel-on-CPU
   state while independently tracking balanced `syscall` and `mach_trap`
   entry/return state per thread. Kernel samples inside those named entry
   states are reported separately; the remaining kernel samples form the
   non-syscall bucket. An entry is balanced by its return or by a matching
   thread/process-exit lifecycle event for a non-returning terminal call.
   Every other imbalance invalidates that profile.
9. Carrick and the native-arm64 Docker oracle never run concurrently. Docker
   remains a correctness oracle and is not an arm of the native CPU ABBA.
10. New hypotheses are active in the spike binary by default. The paired
   control explicitly opts out with `CARRICK_DISABLE_<HYPOTHESIS>=1`.
11. `carrick trace` remains the product tracer. New profiles, typed events,
    validation, and JSON publication extend it instead of creating a parallel
    launch mechanism.
12. LLDB is required whenever the conclusion depends on exact live mappings,
    JIT bytes, registers, or a state that DTrace perturbs or cannot retain.
13. All implementation and profile tests are red-first. A profile that drops,
    truncates, loses its process tree, or cannot reconcile its event
    populations publishes no accepted attribution.

## 3. Scope and non-goals

### In scope

- one checked-in, fail-closed ABBA runner for the primary workload;
- reproducible receipts for same-binary variant comparisons and two-binary
  commit comparisons;
- typed private/shared translated-range observability consumed by
  `native-wall`;
- a launch-owned `native-faults` DTrace profile using live-qualified
  `vminfo:::as_fault` and `vminfo:::zfod` 16 KiB host-page addresses, while
  keeping COW and other unqualified outcomes count-only;
- low-frequency native mapping catalogs for address ownership;
- versioned raw and analyzed artifacts with explicit reconciliation;
- an opt-out hypothesis protocol and LLDB escalation contract; and
- one accepted `I0` evidence set that selects the next optimization slice.

### Out of scope

- changing sharing, translation layout, code generation, memory reservation,
  page protections, scavenging, or fault policy;
- treating the currently opt-in shared cache as ready to ship;
- changing the primary workload, the frozen historical commit, or the 0.70
  destination;
- interpreting traced absolute time as production performance;
- reading Linux kernel or other GPL implementation source; and
- generalizing the new fault profile to FreeBSD or NetBSD before the Darwin
  contract is accepted.

## 4. Evidence architecture

The control plane has three independent evidence paths:

1. `native_go_build.py` executes samples; the ABBA runner controls order,
   receipts, statistics, and acceptance.
2. Carrick USDT events describe process images and every translated-code
   range; `native-wall.d` samples PCs; `native_wall_attribution.py` assigns
   CPU and blocking cost.
3. Carrick USDT events describe native mapping classes;
   `native-faults.d` records separately qualified `as_fault` and `zfod`
   host-page addresses plus count-only outcomes;
   `native_fault_attribution.py` derives 16 KiB page ownership and repetition.

The paths meet only in an evidence manifest. Raw trace counts, sampled shares,
and untraced CPU remain separate fields. The manifest may derive an estimated
CPU ceiling, but it never adds overlapping sample and event populations.

All durable artifacts use atomic publication. Raw streams remain available
for audit; an analyzed artifact records the raw file SHA-256 and rejects a
changed source.

## 5. Untraced ABBA runner

### 5.1 Files and reuse

The executable driver is `scripts/perf/native_go_build_abba.py`. It extends
and calls `native_go_build.run_sample` for the workload, run-ID cleanup, output
markers, CPU collection, image identity, environment scrubbing, and pre/post
provenance.

The runner keeps three paths distinct:

- `harness_repo`: the current checked-in workload and scoped `kill.sh`, shared
  by both arms;
- `receipt.source_repo`: the clean worktree that produced one immutable
  binary, consulted only for source/build provenance; and
- `receipt.binary_path`: the copied executable that the sample actually runs.

`run_sample` gains an explicit binary argument and passes it through
`build_command` and both provenance snapshots. A Carrick sample without that
argument retains the current default for compatibility. The ABBA runner never
uses the default. This prevents a historical receipt from silently executing
`harness_repo/target/release/carrick` and keeps both arms on identical current
workload/cleanup semantics.

Paired statistics live in one Python module,
`scripts/perf/paired_stats.py`. `native_go_build_screen.py` and other Python
campaign drivers migrate to that module or become compatibility front ends;
they do not retain private bootstrap implementations. Golden fixture vectors
also exercise `crates/carrick-cli/src/perf_stats.rs`, preventing the Rust and
Python evidence paths from silently adopting different ratio semantics.

The missing `abbascreen.sh`, `abbavariant.sh`, and `abbastats.py` names are not
recreated. The Python driver replaces their intended role with a typed
artifact and tests.

### 5.2 Artifact receipts

The driver has a `prepare-arm` subcommand. It runs against a clean source
worktree after `just build`, copies the release binary to an immutable
campaign directory, and atomically emits
`carrick.native-perf-arm.v1.json`.

An arm receipt contains:

- label and role (`control` or `candidate`);
- source repository absolute path, clean commit, branch, and status;
- copied binary absolute path, size, mode, SHA-256, and Mach-O UUID;
- `codesign --verify --strict` result and entitlement digest;
- `__DATA,__dof_carrick` presence;
- Rust toolchain, build command, build start/end timestamps, and exit status;
- host architecture and OS build; and
- OCI image reference, architecture, image ID, and immutable repo digests.

The run phase accepts receipts, never an unreceipted binary path. It re-hashes
and re-verifies each binary before the campaign and before every quad. A
receipt is invalid if its file, signature, DOF section, image identity, or
source cleanliness differs. Two-binary comparisons use separate clean source
worktrees so one arm cannot invalidate the other's recorded commit.

### 5.3 Comparison modes

There are exactly two arm modes:

- **same binary:** both arms name the same receipt and differ only by complete,
  scrubbed environment overlays;
- **two binary:** each arm names a distinct receipt, and both use the same
  complete environment overlay.

The schema records the mode. Mixing binary and environment differences in one
comparison is rejected because attribution would be ambiguous.

Legacy observational comparisons use `default` versus `shared`. They do not
use `candidate`, because the current `candidate` overlay also enables the
artifact spike. A new optimization spike uses the same binary with:

- candidate: `CARRICK_DISABLE_<HYPOTHESIS>` absent;
- control: `CARRICK_DISABLE_<HYPOTHESIS>=1`.

The disable key is added to `PERFORMANCE_CONTROL_KEYS`; ambient `CARRICK_*`
values remain contamination.

### 5.4 Schedule

An official campaign starts with excluded warm-ups in `A, B` order, then runs
at least eight complete quads. Every quad is:

`A1, B1, B2, A2`

where `A` is control and `B` is candidate. Samples are serial. Every sample
uses a unique run ID and empty `GOCACHE`, then performs scoped cleanup before
the next sample. The official default is a two-second cooldown after every
warm-up and measured sample. A different cooldown requires a new campaign
identity and applies to both arms.

The average of the two positions forms each arm's quad value:

- `Aq = (A1 + A2) / 2`
- `Bq = (B1 + B2) / 2`
- `Rq = Bq / Aq`

The same calculation is made separately for total CPU, user CPU, system CPU,
full wall, and workload wall. Total CPU is primary.

### 5.5 Statistics and decisions

For each metric the artifact reports:

- all raw samples and quad membership;
- arm medians and median quad ratio;
- arithmetic and log-ratio standard deviation;
- candidate wins (`Bq < Aq`), with exact-equality ties retained in descriptive
  statistics but removed from the sign-test `n`;
- the exact one-sided sign-test probability
  `P(Binomial(n, 0.5) >= candidate_wins)`;
- a seeded 100,000-resample paired bootstrap that resamples whole quads;
- two-sided 95% and one-sided 95% ratio bounds; and
- the normal-approximation smallest resolvable ratio effect at the current quad
  count.

Each bootstrap draw samples `n` complete `Rq` values with replacement and
takes their median. The two-sided interval uses nearest-rank 2.5% and 97.5%
quantiles; the one-sided upper bound uses the nearest-rank 95% quantile. The
bootstrap seed, draw count, quantile rule, and formulas are schema fields. No
tool may silently choose its own defaults.

The resample stream is also part of the contract:

- PRNG `splitmix64-v1` advances a wrapping 64-bit state by
  `0x9e3779b97f4a7c15`, sets `z = state`,
  `z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9`,
  `z = (z ^ (z >> 27)) * 0x94d049bb133111eb`, and returns
  `z ^ (z >> 31)`; every addition and multiplication wraps modulo `2^64`;
- sampler `u64-rejection-mod-v1` sets
  `limit = 2^64 - (2^64 mod n)`, rejects outputs `x >= limit`, and uses
  `x mod n`; `limit` is computed in unsigned 128-bit arithmetic and may equal
  `2^64`, and rejected outputs still advance the one persistent PRNG state;
- each replicate consumes exactly `n` accepted indices, and the state
  continues across all 100,000 replicates;
- the official initial state/seed is the hexadecimal string
  `0x4341525249434b31`;
- an odd replicate median is its middle sorted value, while an even median is
  the binary64 arithmetic mean of its two middle sorted values; and
- nearest-rank percentile `p` is sorted element
  `max(1, ceil(p * draws)) - 1` in zero-based indexing.

The schema records the PRNG ID, sampler ID, seed string, accepted-index count,
rejection count, median rule, and quantile rule. Golden fixtures compare the
first index prefix and every final binary64 bound by its raw 64-bit encoding,
not by implementation-specific JSON formatting.

The descriptive resolution floor exactly preserves the controller's existing
calculation. Let `sR` be the Bessel-corrected sample standard deviation of the
`n` complete raw quad ratios `Rq`. With
`z95 = 1.6448536269514722`:

- `resolution_fraction = z95 * sR / sqrt(n)`;
- `smallest_resolvable_improvement_ratio = 1 - resolution_fraction`; and
- `smallest_resolvable_effect_percent = 100 * resolution_fraction`.

The artifact stores `n`, `sR`, `z95`, all three derived fields, and the formula
identifier `normal-one-sided-ratio-sd-v1`. This normal approximation is a
planning diagnostic, not a retention confidence bound; the paired bootstrap
and sign test remain authoritative. Rust/Python golden fixtures use the same
unrounded inputs and round only for display.

A normal optimization slice is retained only when:

1. the predeclared mechanism moves in the traced or exact-count evidence;
2. total-CPU median quad ratio is below 1.0;
3. its one-sided 95% upper bound is below 1.0;
4. its one-sided sign test is below 0.05;
5. no secondary metric has a statistically supported regression, defined as
   a two-sided 95% lower ratio bound above 1.0; and
6. focused and end-to-end correctness gates pass.

The full campaign succeeds only when every retained wave has condition 1
mechanism evidence and a two-binary `H0` / final-tip comparison meets
conditions 2–6 with a total-CPU ratio at most 0.70.

### 5.6 Preflight and failure behavior

Every quad repeats the current workload contamination census. The runner
rejects:

- a dirty source tree or changed receipt;
- foreign Carrick/performance processes or a running Docker oracle;
- active `cargo`, `rustc`, or known spin workloads;
- one-minute load above the host logical-CPU count;
- battery power or a reported thermal/power warning;
- an unknown ambient `CARRICK_*` variable;
- a failed workload marker, invalid workload clock, timeout, or nonzero exit;
- failed scoped cleanup; or
- pre/post provenance drift.

The census reads the full `ps -axww` command/proctitle, not only executable
basenames. In addition to known executable paths, it recognizes any delimited
`carrick:<run-id>:` proctitle using the same authority as
`scripts/sudo/kill.sh`. It excludes only the current runner ancestry and the
exact current run ID. A stale `carrick:native-go-build-...:` process is
therefore a foreign Carrick process even when the executable name has been
rewritten. The runner reports it and fails closed; it never kills a foreign
run automatically.

The output schema is `carrick.native-go-build-abba.v1`. The runner writes a
partial artifact after every sample. Any failure marks it `complete=false`,
`accepted=false`, records the evidence and reason, and exits nonzero. Partial
campaigns cannot resume into an official result; all official quads restart
under one host-state window.

## 6. Typed translated-range catalog

### 6.1 Problem

`host-jit-range` currently announces the private process cache from
`native_darwin.rs`. Shared units announce `dsr_cache_bounds` inside the
translator, while the native-wall path retains only one current JIT range per
PID. A run with dozens of `dlopen`ed shared units can therefore charge shared
execution to Darwin userspace, host code, or unresolved PCs. Translation
locality conclusions drawn from that output are invalid.

### 6.2 Runtime domain

`carrick-observability` gains typed Rust values:

- `TranslatedRangeKind::{PrivateProcessCache, SharedUnit}`;
- `TranslatedRangeReset`;
- `TranslatedRangeAdd`, containing kind, half-open `HostVa` range, and typed
  unit identity; and
- `TranslatedRangeReady`.

There is no general raw-integer constructor. `start < end`, AArch64
instruction alignment, monotonic sequence, and legal identity are validated
before publication. The range is the exact executable extent; it is not
expanded to page boundaries that could capture unrelated PCs.

The USDT crate caps probes at six arguments. The wire contract therefore uses
separate scalar probes instead of packing raw action/kind integers:

- `host-translated-range-reset(pid, epoch)`;
- `host-translated-private-range(pid, epoch, sequence, start, end)`;
- `host-translated-shared-range(pid, epoch, sequence, unit_id, start, end)`;
- `host-translated-range-ready(pid, epoch, final_sequence)`.

Typed wrappers are the only call sites for those probes. Provider names carry
the action and kind domains; the USDT boundary does not expose a generic raw
action/kind parameter.

Translated mappings are immutable for one process-image epoch. Private caches
and loaded shared units remain mapped until exec or exit. If runtime work
introduces unload or address reuse, this design no longer applies: a typed
`Remove` transition and sample-time catalog semantics require a new review
before the profile can accept that run.

### 6.3 Epoch lifecycle

`ProcessTranslator` / `ProcessState` owns one idempotent catalog publisher for
the whole process. The per-thread loop-entry `host_jit_range` compatibility
call does not own reset/replay. This prevents sibling guest threads from
racing or duplicating a process catalog.

Each host process image owns a fresh nonzero runtime epoch and sequence:

1. `Reset(epoch)` invalidates prior state and sets the next sequence to one.
2. The private cache and every already loaded shared unit replay as ordered
   `Add` events before translated guest execution.
3. `Ready(epoch, final_sequence)` closes the initial replay. Later monotonic
   shared-unit additions remain legal.
4. A newly published shared unit emits `Add` before any link can make its code
   reachable.
5. In `ThreadTranslator::after_fork_child`, the child receives a fresh epoch
   after `self.process.after_fork_child()` and performs the idempotent
   reset/replay before entering guest code.
6. A successful host self-reexec clears the DTrace-side catalog at
   `proc:::exec-success`; the new image emits a fresh reset and replay.
7. Exit retires the epoch.

DTrace does not allocate a process ID with a shared increment: global
read/modify/write state is not safe under concurrent `proc:::create` probes.
The raw wire identity is instead an immutable `ProcessBirthKey`:
`(pid, pr_start_tv.tv_sec, pr_start_tv.tv_usec)`, read from `curpsinfo` for
current-process probes and `args[0]` for the child at `proc:::create`. Live
compile probes on this Darwin build confirm all three fields, but they are an
evolving/private translator contract. Every profile therefore runs a
launch-time parent/fork fixture proving that one process keeps a stable key and
its child gets a distinct key. The raw header records the OS build and D
program hash; failure publishes no profile.

The initial target emits `TargetBirth` before any sample is accepted, and each
child emits `ProcessCreate(child_birth_key, parent_birth_key)`. Each birth key
starts at `image_generation=1`; `proc:::exec-success` increments that key's
generation. The runtime epoch is nested beneath those two identities and may
restart after self-reexec. Raw records use
`(birth_key, image_generation, runtime_epoch)`.

`trace_profile.rs` validates the complete lifecycle, assigns target
`process_instance=1`, and assigns dense presentation IDs 2..N to admitted child
birth keys sorted by `(start_sec, start_usec, pid)`. The published
process-image key is
`(process_instance, image_generation, runtime_epoch)`. It rejects a birth key
seen before admission, a second create for the same key, a changed birth key
without a PID lifecycle transition, or any reuse of a retired key. PID and
birth time remain in every JSON identity record; `process_instance` is an
offline label, never an in-kernel allocator.

CPU, off-CPU PC/duration, user stack, host/guest image, translated range, and
mapping-catalog records all carry the raw birth key and nested generations. At
`proc:::create`, the child emits a `ForkInherit` relation containing both birth
keys, the parent's current image/runtime key, translated-range sequence
frontier, and mapping-catalog version. The offline validator materializes
exactly the observed catalog prefix through those fork-time frontiers into the
child's first image generation; it never aliases the parent's eventual
catalog, which may gain later shared-unit additions. Each frontier must exist
in the contiguous parent stream or the profile is invalid. The D program does
not attempt to copy an arbitrary range set inside `proc:::create`. Reset
switches the child to a fresh runtime epoch. An off-CPU episode latches the raw
complete key at block time; a wake observed under a different key invalidates
the episode rather than merging it. Samples before the first runtime epoch
announcement use epoch zero and can resolve only as host/Darwin/unresolved,
never as translated code. This keeps PID reuse, host startup, and self-reexec
samples from being retroactively assigned to a later mapping at the same
address.

Unknown epochs, duplicate sequences, gaps, additions before reset, overlapping
private/shared ranges, duplicate identities with different bounds, and
post-exec samples using a retired epoch make the profile incomplete. Every
process epoch that enters the native DSR loop must reach `Ready`;
`final_sequence` must equal the initial replay cardinality, later additions
must remain contiguous, and the final runtime catalog count must equal the
last sequence.

### 6.4 Probe and compatibility contract

The existing `host-jit-range` probe remains for script compatibility. The new
typed event is the authority for native-wall classification. Both are
low-frequency announcements; no event fires per translation or per sampled
instruction.

`native-wall.d` emits a new `DSRPROF2` raw grammar. Every CPU, off-CPU, stack,
image, translated-range, mapping-catalog, lifecycle, and reconciliation record
carries `ProcessBirthKey`, image generation, and runtime epoch. Catalog records
use v2 record tags under that grammar rather than reusing PID-only v1 prefixes.
`trace_profile.rs` validates the epoch state machines before atomically
publishing `carrick.dsr-profile.v2` JSON.

The parser rejects a mixed v1/v2 stream. Existing `DSRPROF1` and
`carrick.dsr-profile.v1` artifacts remain readable only through a
non-gating compatibility path; they cannot satisfy this design's attribution
or acceptance gates. Unknown v2 record tags are fatal rather than ignored.

Host image base and `host-image-catalog` announcements also become
process-image-epoch keyed. The current PID-only `catalog_seen` state is not
retained across self-reexec. Fork provisionally inherits the parent's host
catalog; exec retires it and requires a new base/catalog before host PCs in the
new epoch can count as resolved.

The existing `guest-image-base` event remains compatibility metadata. Its
base, entry, and path do not imply an executable extent, so it cannot classify
a user PC. `native-wall` makes no guest-native-executable bucket in this
design. Any non-JIT guest PC that is not owned by an exact host image/symbol
rule remains `unresolved` and counts against the coverage gate.

`scripts/dtrace/native-jit-aware-profile.d` is no longer an evidence authority.
Its one-range-at-a-time predicate cannot classify an arbitrary set of shared
unit mappings without another lossy range model. It is replaced by, or reduced
to a clearly non-gating compatibility front end for, the epoch-aware
`native-wall` capture and offline analyzer. There is one accepted translated-PC
classifier in the repository.

`native_wall_attribution.py` uses this non-overlapping top-level taxonomy:

1. `private-translated`;
2. `shared-translated`;
3. `translation-build`;
4. `translation-publication`;
5. `gateway-prepare`;
6. `gateway-resolve`;
7. `dispatch`;
8. `process-setup`;
9. `other-carrick`;
10. `darwin-userspace`;
11. `kernel-named-syscall`;
12. `kernel-mach-trap`;
13. `kernel-non-syscall`; and
14. `unresolved`.

The first two categories are exact range joins in the listed order.
Carrick-resident categories use a checked-in, ordered, first-match symbol-rule
table only after all exact range joins fail. Its fixture enumerates every
covered symbol and fails if a symbol matches more than one rule. Darwin image
catalog ownership supplies `darwin-userspace`; it does not infer a Carrick
caller from a leaf PC. Kernel categories come from the independent balanced
entry state below, never from user-symbol rules. A record receives exactly one
top-level category or the profile is invalid.

`native-wall.d` also folds in the balanced `syscall` and `mach_trap`
entry/return state used by `native-whole-cpu-budget.d`. Kernel samples are
partitioned into named-syscall, mach-trap, and non-syscall buckets at sample
time. Simultaneous syscall and mach-trap state is invalid. The parser
reconciles every entry against a return or an explicit
`proc:::lwp-exit`/`proc:::exit` terminal closure and rejects any other open
thread state at completion.

An accepted profile retains the current gates:

- natural target completion, reconciled process live set, and zero drops;
- at least 99% wall-state coverage;
- at least 85% resolved CPU coverage;
- at least 80% top blocking-stack coverage; and
- two complete runs with stable dominant-category rank and no category above
  10% moving more than five percentage points without an instability finding.

In addition, every native DSR process epoch must reach `Ready`, the initial
replay cardinality must match its final sequence, later additions must remain
contiguous, every PC classified as translated must resolve to exactly one
typed range kind, and every range epoch must reconcile. Unknown PCs remain
unknown and continue to count against the 85% coverage gate; they are never
silently relabeled as host code.

## 7. Native fault-address profile

### 7.1 Ground truth and private-provider qualification

Probe presence is not evidence that a probe is on the active path. On macOS
27.0 build `26A5388g`, live kernel-only censuses established:

- a PID-scoped anonymous-touch fixture produced 16,407
  `vminfo:::as_fault` events and zero `fbt::vm_fault:entry` events;
- a global three-second census produced 52,440 `as_fault`, zero `vm_fault`,
  and only 18 `vm_fault_external` events; and
- `fbt::vm_fault:entry` still appears in `dtrace -lvn` with the previously
  assumed address argument.

`fbt::vm_fault` is therefore explicitly disqualified for this host. A
type/presence preflight would have accepted a dead path and is not used.

The same live work found an active but private interface. `dtrace -lvn`
declares no arguments for `vminfo`, yet controlled anonymous touches show:

- `vminfo:::as_fault` `arg2` is the 16 KiB host-page base containing the
  faulting access;
- `vminfo:::zfod` `arg2` is the same host-page address domain; and
- `vminfo:::cow_fault` `arg2` is not a virtual address on this host.

The 4 KiB access offset is not preserved. For example, distinct touches inside
one 16 KiB page produce the same page-base value. The profile therefore makes
no 4 KiB fault-address or COW-address claim.

Because those `vminfo` arguments are private and probe-specific, a checked-in
live qualification precedes every campaign and is keyed by:

- product version, OS build, Darwin kernel version/UUID, architecture, boot
  identity, and `hw.pagesize`;
- qualification binary, D program, and analyzer SHA-256; and
- exact provider/probe names.

The hidden Carrick command `__native-fault-abi-fixture` creates isolated
anonymous mappings, announces exact mapping/touch ranges and phase
start/finish through low-rate USDT probes, and performs:

1. first touches at different 4 KiB offsets in known 16 KiB host pages;
2. repeated touches within an already populated host page;
3. first touches in several consecutive host pages; and
4. a fork/write COW phase whose outcome is count-only.

`scripts/dtrace/native-fault-qualify.d` records raw `arg0` through `arg4` for
the fixture PID/process tree without interpreting them. The validator emits
`carrick.native-fault-provider.v1.json` only when:

- `as_fault` and `zfod` independently put the expected host-page base in
  `arg2`;
- events selected inside the announced qualification phase and mapping use
  the observed 16 KiB stride;
- multiple 4 KiB offsets in one host page do not masquerade as distinct
  addressable pages;
- PID/progeny scoping excludes a simultaneous control process;
- addressed-event populations inside the qualification mapping match the
  fixture's declared expectation; unrelated process-startup addresses remain
  visible in the raw receipt but do not count toward that expectation;
- the COW phase proves only a count and does not pass its `arg2` as an address;
  and
- completion and drop counters reconcile.

A host/build that fails qualification has no accepted address profile. It may
still report clearly labeled unaddressed global counts, but those counts cannot
select an address or mapping optimization. Adding another address-bearing
provider requires a new live fixture and design review.

### 7.2 CLI and process identity

`TraceProfileKind` gains `NativeFaults`, exposed as:

```text
carrick trace --profile native-faults \
  --fault-qualification <provider-receipt.json> \
  --trace-out <raw> --summary-jsonl <summary> -- \
  run --exec-backend native <image> <command>
```

The bundled program is `scripts/dtrace/native-faults.d`. It uses the existing
libdtrace launch/credential/process-tree machinery and publishes through
`trace_profile.rs`. The offline analyzer is
`scripts/perf/native_fault_attribution.py`; its output schema is
`carrick.native-fault-attribution.v1`.

The receipt must match the live host/boot and exact D program. The trace
refuses a stale or differently qualified receipt.

The tracked set starts at `$target`, admits only children observed through
`proc:::create`, survives exec, and retires on exit. Raw fault keys use the
same `ProcessBirthKey`/image-generation/runtime-epoch identity as the mapping
catalog; the offline validator replaces the birth key with its dense
`process_instance` label only after lifecycle validation. PID reuse or
self-reexec cannot merge pages. Unrelated Carrick processes never enter.

For `as_fault` and `zfod`, the D program preserves exact `arg2` and aggregates
by `(birth_key, image_generation, runtime_epoch,
mapping_catalog_version, outcome, host_page_base)`. It validates host-page
alignment but does not clear low bits to manufacture a passing value. COW and
every other unqualified `vminfo` outcome aggregate only by
`(birth_key, image_generation, runtime_epoch, outcome)`, with no
address or mapping-version field. Outcome populations are independent
counters, not an exclusive partition or a per-fault join.

Launch startup and exec transitions precede a ready runtime catalog. Epoch
zero/version zero is therefore an explicit **attribution-disabled** state, not
an invented `HostOther` catalog. The D program counts every `as_fault` and
`zfod` event in that state as a separate count-only
`pre_catalog_or_transition` population and does not create a page-ownership
record. Once catalog version one reaches `Ready`, address attribution becomes
armed atomically. A forked child may start armed from the exact inherited
frontiers in `ForkInherit`. `proc:::exec` disarms attribution before image
replacement; `proc:::exec-success` retires the old image, increments its
generation, and remains disarmed until the new image's first catalog is ready;
`proc:::exec-failure` restores the prior ready catalog without incrementing
generation. Events during either attempted-exec transition stay in the
count-only population. Later catalog replacement keeps the prior immutable
version active until the next version reaches `Ready`.

For each outcome, the all-tracked total must equal address-attributed events
plus the attribution-disabled count. The analyzer reports both populations
and `address_attribution_coverage`; an excluded startup event is never silently
dropped or relabeled.

### 7.3 Native mapping catalog

Carrick publishes a closure-gated `host-native-map-catalog` snapshot only when
a live consumer is attached. Its Rust domain is an ordinal
`NativeMappingClass` enum, not stringly typed call sites:

- `GuestImage`
- `GuestHeap`
- `GuestMmapArena`
- `GuestStack`
- `SigreturnTrampoline`
- `SharedFileAperture`
- `PrivateOverlay`
- `PrivateTranslated`
- `SharedTranslated`
- `OtherOwned`

The snapshot derives guest host ranges from the existing `AddressSpace`,
`MemoryLayout`, `NativeAddressMode`, and `owned_host_ranges` authorities. The
pure range construction currently used by mapping-class tests becomes shared
production/test logic; a second layout model is not introduced.

This is deliberately a **host-backing ownership catalog**, not a guest VMA or
permission catalog. Native Darwin's `PageAligned` loader has already rounded
ELF segments to the 16 KiB host page and does not retain every original 4 KiB
executable boundary; later `mprotect` changes live guest permissions without
rewriting `AddressSpace`. The catalog therefore publishes no R/W/X field,
makes no exact 4 KiB ELF claim, and is not consumed as a PC-executable range.
`GuestImage` means loader-owned host backing, including its host-page padding.
Heap and mmap classes mean Carrick's stable backing reservoirs, whether or not
every guest page is currently a live VMA.

Ranges are half-open and retain the exact ownership boundaries available from
their named runtime authorities. The builder removes layout-known stack,
trampoline, aperture, and translated-cache ranges before labeling remaining
loader-owned regions as `GuestImage`, then subtracts every declared class from
`owned_host_ranges` to form `OtherOwned`. Catalog validation rejects overlap,
missing owned ranges, impossible address translations, and uncovered bytes
inside the declared ownership universe. Addresses outside that universe
remain `HostOther`; they are not silently called guest memory.

Each runtime epoch starts with mapping-catalog version one. A guest
`mmap`/`mprotect`/`munmap` wholly inside an already classified backing
reservoir does not change host ownership and emits nothing. A successful
operation that adds, removes, or reclasses an `owned_host_ranges` extent
publishes a complete next-version snapshot before that ownership becomes
observable to guest execution. Failed or rolled-back operations publish
nothing. Versions are contiguous and immutable. Exec starts a fresh runtime
epoch; fork latches the parent's exact version in `ForkInherit` and the child
replays its inherited snapshot before execution. The translated-range epoch
and mapping-catalog runtime epoch must agree, while their sequence/version
frontiers reconcile independently.

The composite catalog is closure-gated like `host-image-catalog`, but its
probe also carries scalar process-image identity and runtime mapping epoch
plus mapping-catalog version arguments so the D program can key faults without
parsing JSON in-kernel. The serialized catalog is copied only for publication
and validated again by `trace_profile.rs`.

### 7.4 Aggregation and analysis

The D program cannot and does not perform a dynamic range join inside the hot
kernel probe. The offline analyzer joins each qualified 16 KiB host-page base
to the exact validated host-ownership catalog version recorded with the event.

One host page may intersect multiple declared ownership fragments. Its
ownership is:

- `Uniform(class)` when the entire page is covered by one class;
- `Mixed(class-set)` when two or more classes share the host page;
- `Partial(class-set)` when declared and undeclared bytes share it; or
- `HostOther` when no declared Carrick mapping covers it.

Mixed/partial pages remain their own buckets. Fractional ownership composition
is reported descriptively, but an event is never assigned to one favored
fragment. Exact guest-subpage access or live permissions require a separately
designed guest-VMA/access census.

For each addressed outcome (`as_fault`, `zfod`), process instance, and
ownership bucket, the analyzer reports:

- event count and distinct qualified 16 KiB host pages;
- repeat excess (`events - distinct_host_pages`);
- repeat factor (`events / distinct_host_pages`);
- uniform, mixed, partial, and `HostOther` populations;
- the declared ownership-fragment composition of mixed pages; and
- the highest-count host pages, with reversible guest-page candidates when
  the address mode permits.

It separately reports unaddressed COW/pagein/major/protection/real-fault totals
without mapping ownership. It reports no return result, `vm_tag`, requested
protection, wiring state, or exact 4 KiB fault address because no active
qualified provider supplies them. Exact event counts and sampled kernel CPU
remain separate tables. It also reports pre-catalog/transition `as_fault` and
`zfod` totals and their share of all tracked address-bearing outcomes.

The raw DTrace aggregation is high-cardinality by design. Buffer,
aggregation, or dynamic-variable drops invalidate the run. If the primary
workload exceeds the configured cardinality budget, no page claim is
published. A subsequent design may add an evidence-selected class filter; it
may not silently truncate the page table or substitute a sampled address
census.

### 7.5 Acceptance

A native-faults artifact is accepted only when:

- its provider receipt matches the current host, boot, script, and qualified
  `as_fault`/`zfod` argument contract;
- the target exits naturally with the workload markers present;
- the tracked live set reaches zero;
- all-tracked `as_fault` and `zfod` totals equal their page aggregations plus
  explicit attribution-disabled startup/transition counts;
- combined `as_fault`/`zfod` address-attribution coverage is at least 85%;
- every address-attributed value is 16 KiB aligned under the qualified
  contract;
- every page has one uniform/mixed/partial/`HostOther` ownership result;
- COW and other count-only outcomes have no address or ownership fields;
- process/image/runtime epochs reconcile, mapping-catalog versions are
  contiguous, and every address-attributed event names a ready published
  version;
- overflow and drop counters are zero; and
- two primary-workload runs agree on the dominant ownership-bucket rank,
  while every bucket above 10% differs by no more than five percentage points
  or carries an explicit instability finding.

## 8. Hypothesis and spike protocol

Every optimization hypothesis enters the durable evidence ledger with:

- observation, raw artifact hashes, and current validity;
- measured share or exact event population;
- a conservative CPU-seconds ceiling;
- predicted counter and category movement;
- structural mechanism and correctness risk;
- the opt-out control variable;
- bounded implementation variants and stop condition;
- traced mechanism result;
- untraced ABBA result; and
- `PROPOSED`, `SPIKING`, `RETAIN`, `REJECT`, or `DEFER`.

A spike proceeds in this order:

1. Predeclare the mechanism, expected range/fault/counter movement, direction
   of total/user/system CPU, maximum variants, rejection condition, and the
   accepted baseline attribution that sizes its ceiling.
2. Add the smallest red-first correctness proof that makes the spike safe to
   run.
3. Implement the candidate as the normal path and the control as
   `CARRICK_DISABLE_<HYPOTHESIS>=1`.
4. Run the focused DTrace profile or exact counter gate needed to prove the
   predeclared mechanism. DTrace timing itself is ignored. A mechanism that
   does not move stops here.
5. Run a complete two-quad ABBA screen. It is exploratory and cannot retain a
   candidate. A clearly neutral or regressive candidate stops here, but the
   screen makes no claim about whether the mechanism moved.
6. Run the eight-quad untraced retention campaign.
7. Retain only if the statistical and correctness gates in section 5 pass.
8. Refresh `I0`-relative attribution and rerank the remaining ceilings.

An opt-out flag stays through the next accepted baseline so the same binary can
still reproduce its control. It is removed in a later cleanup only after the
retained behavior has an independent binary comparison and no active
diagnostic needs the control.

The first evidence questions are fixed:

- **translation:** on `default` and `shared`, how much sampled execution is
  private versus shared, how many distinct ranges/units contribute, and does
  the shared path scatter execution across enough mappings to explain its
  worse CPU despite fewer translations?
- **kernel:** under the qualified provider contract, which
  uniform/mixed/partial mapping buckets own addressed `as_fault` and `zfod`,
  how much repetition occurs on the same 16 KiB host pages, and how large are
  the separate count-only COW and other populations?

The larger conservative removable CPU ceiling selects the next subproject.
Ties go to the change with the narrower correctness surface. No runtime
optimization begins merely because one question sounds more plausible.

## 9. LLDB escalation contract

LLDB/core evidence is mandatory when:

- a dominant `HostOther` or overlapping address needs a concrete VM region
  owner;
- a sampled PC lies in a range whose bytes or publication state are disputed;
- a fork/exec child does not replay the expected catalog;
- exact guest/host registers or recovery state determine correctness;
- DTrace makes the failure disappear or changes the process topology; or
- the process wedges while collecting an evidence run.

The debugger attaches to the guest Carrick process, not the orchestrator
parent. A wedge gets a real core and `bt all`; `sample` and `SIGQUIT` are not
accepted substitutes. The always-on event ring is read through
`scripts/carrick_lldb.py` before adding new hot-path instrumentation.

Each debugger finding records the binary hash, PID/run ID, command file, core
or transcript path and SHA-256, relevant mappings/registers, and the exact
claim it proves or falsifies. Debugger observations remain mechanism evidence;
the untraced ABBA still decides performance.

## 10. Red-first tests and live proof

### ABBA and receipts

- schedule, warm-up exclusion, quad pairing, sign test, paired bootstrap, and
  confidence-bound fixtures;
- equality with shared Rust/Python golden statistics;
- rejection of mixed arm modes, dirty receipts, hash/signature/DOF drift,
  ambient controls, partial quads, cleanup failure, and failed markers;
- contamination fixtures for executable-path matches and the live
  `carrick:native-go-build-...:` rewritten-proctitle orphan shape;
- crash-safe partial publication; and
- a control/control live campaign that correctly produces evidence without
  falsely declaring an optimization win.

### Translated ranges

- a parser fixture that the old one-range model misclassifies when two shared
  units exist, then green classification under the typed catalog;
- enum ordinal uniqueness and invalid-range rejection;
- reset/add sequence, overlap, gap, duplicate, fork replay, and exec reset
  tests;
- private-only and private-plus-shared live profiles; and
- proof that no translated sample remains outside exactly one typed range.

### Native faults

- live qualification fixtures for active `as_fault`/`zfod` `arg2`, 16 KiB
  alignment, COW count-only behavior, process-tree scoping, and stale-receipt
  rejection;
- parser rejection fixtures for PID reuse collisions, self-reexec generation
  mistakes, an addressed COW record, misaligned private-provider data,
  overflowed, dropped, and truncated streams;
- startup, exec-transition, and fork-inherited fixtures that reconcile
  attribution-disabled counts and reject address attribution before `Ready`;
- mixed/partial 16 KiB host-page ownership and repeat-factor fixtures;
- mapping-class overlap and coverage tests;
- a native guest fixture that faults known anonymous host pages and proves
  separately qualified `as_fault`/`zfod` page bases and mapping ownership,
  without claiming an exact 4 KiB access, return result, or COW address;
- fork and self-reexec fixtures proving catalog lifecycle; and
- two complete primary-workload captures meeting section 7.5.

Tests first fail against the old binary or deliberately corrupted fixture.
After implementation, the control-plane slice passes:

- focused Rust and Python tests;
- live `carrick trace --profile native-wall`;
- live `carrick trace --profile native-faults`;
- the cold-`GOCACHE` Go compile-and-run marker;
- `just conformance-native smoke --workers 4`;
- Node V8 and CPython threading/subprocess guardrails when range or fork/exec
  lifecycle changes;
- `just ci`; and
- the control-plane neutrality ABBA against `H0`.

## 11. Delivery sequence

### M0 — approved controller

This design is reviewed, committed, and converted into an executable
implementation plan.

### M1 — untraced authority

The arm receipt, shared paired statistics, and eight-quad ABBA runner are
checked in. Unit tests, failure fixtures, and a live control/control campaign
prove the evidence behavior.

### M2 — translation ownership

Typed range epochs land, `native-wall` consumes them, fork/exec lifecycle is
live-proven, and accepted `default` and `shared` captures report private/shared
execution without range ambiguity.

### M3 — fault ownership

The private-provider qualification receipt, `native-faults`, and the mapping
catalog land. The known-host-page fixture proves qualified `as_fault`/`zfod`
addressing and count-only COW semantics; two primary-workload captures meet
every reconciliation gate.

### M4 — `I0` and next slice

The instrumentation-neutrality comparison passes. `I0` stores untraced ABBA,
two native-wall profiles, two native-faults profiles, hashes, and derived
ceilings. The ledger names exactly one next optimization subproject and its
bounded first hypothesis.

Completing M4 completes this control-plane design, not the active performance
goal.

## 12. Campaign completion

The broader native-performance goal is complete only when:

1. a fresh eight-quad two-binary campaign shows final tip / `H0` total CPU at
   or below 0.70 with the retention confidence gates green;
2. translation-side estimated CPU is materially below `I0`;
3. non-syscall-kernel estimated CPU is materially below `I0`;
4. a final accepted eight-quad same-binary comparison of the semantic
   `default-no-sharing` control and `shared` candidate has
   `shared/default-no-sharing < 1.0` for total CPU, a one-sided 95% CPU upper
   bound below 1.0, a one-sided CPU sign-test probability below 0.05, an A1
   full-wall median ratio at or below 1.0, no statistically supported
   secondary regression, and green correctness gates;
5. sharing is the normal shipped native path without an enable flag, while an
   explicit `CARRICK_DISABLE_SHARED_TRANSLATION=1` opt-out preserves the
   rollback/control arm through the next accepted baseline;
6. full wall and workload wall show no statistically supported regression;
7. native smoke, Node, CPython, and `just ci` gates pass;
8. every retained wave has mechanism evidence and an opt-out control receipt;
9. the final handoff links all raw and analyzed evidence; and
10. active hypotheses are retained, rejected with evidence, or explicitly
   deferred with a measured ceiling.

The sharing artifact uses those semantic arm labels even after the default
flips: the normal path is `shared`, and the opt-out reconstructs
`default-no-sharing`. Merely retaining an opt-in shared mode does not satisfy
"land sharing."

Exhausting the current hypothesis list, reducing translation count, reducing
fault count, or improving a traced run is not completion by itself.

## 13. Stop and redesign conditions

- The ABBA runner stops if its CPU population changes semantics or cannot
  preserve clean provenance across a quad.
- Typed range attribution stops on unload/address reuse, ambiguous overlap, or
  a fork/exec replay gap.
- Native-faults stops on a stale or failed provider qualification, misaligned
  addressed event, epoch/catalog mismatch, or cardinality overflow; it does
  not weaken reconciliation to obtain output.
- A hypothesis stops after two bounded structural variants fail their
  predeclared mechanism or retention gate.
- A correctness obligation requiring a broader runtime architecture change
  gets its own design instead of a performance-only exception.
- The active campaign does not change its primary workload, historical
  baseline, or 0.70 destination to make a disappointing result pass.
