# Native-lane performance handoff

**Date:** 2026-07-31
**Branch:** `codex/native-performance-m1` (recovery-run evidence checkpoint
`b0ddf87d`; performance/timeout checkpoint `47457f44`; qualified profile-v2
checkpoint `edbdc530`; M1 correctness checkpoint `5020e509`)
**Scope:** Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
default). No VMM/HVF/KVM/bhyve behaviour was touched.

> The FreeBSD native x86 bring-up work (`1b55b4b0`, branch
> `perf/native-xstate-transfer`) is unrelated and still open; its live caveat
> stands: **`neutral-domains` remains opt-in — do not make it the production
> default until Tasks 43, 55 and 58 close.**

Historical M1 and pre-M2 evidence is in
[`docs/perf-results/2026-07-29-native-cpu-budget-evidence.md`](docs/perf-results/2026-07-29-native-cpu-budget-evidence.md),
runs 1–31. Current M2 execution state is recorded here and in
`.superpowers/sdd/2026-07-30-native-performance-m2-translation-ownership/`;
its ignored raw trace receipts remain under `target/perf/`.

---

## Active performance checkpoint — retained shared-cache mechanisms

The performance campaign now has direct cumulative and shared/default
measurements. The branch is still active and is **not merge-ready**:
run-encoded recovery metadata is retained, the qualified v2 profiler has a
signed live proof, and the retained shared-translation stack has a clean
cumulative result, but the remaining shared-path user-CPU owner has not yet
been isolated or improved.

Retained default-on changes, each with an exact `=0` opt-out, now remove:

- cloned shared manifests, varint decode overhead, and repeated source hashing;
- eager per-process recovery-action binding, with portable recovery metadata
  additionally run-encoded for lazy fault-time lookup;
- full 60+ MiB dylib reads and SHA-256 rehashes in every descendant, replaced
  by bounded Mach-O reads plus a signed key-specific export identity; and
- indirect copying of instruction bytes where the direct form is proven.

The final two-binary cumulative campaign directly compared clean detached
source commits `04b2222d` and `b0ddf87d`, with shared translation enabled on
both arms. Across eight complete ABBA quads the retained stack won `8/8` and
measured a total-CPU ratio of `0.84499` (`-15.50%`; one-sided upper `0.87124`,
two-sided interval `0.80496..0.88793`, sign probability `1/256`). User CPU fell
`17.40%`, system CPU `10.84%`, outer wall `15.66%`, and guest workload `17.87%`.
This direct result supersedes the former `~21.4%` compounded projection: the
mechanisms overlap more than their isolated measurements implied.

The adjacent same-binary campaign measured the current default path against
the current shared path. Shared translation still costs `6.76%` total CPU
(`8/8` quads favored default; two-sided ratio interval
`1.02327..1.09442`), comprising `+8.49%` user CPU, `+2.93%` system CPU,
`+6.22%` wall, and `+6.74%` guest workload. This replaces the older `+16.46%`
gap: most of it is closed, but the remainder is statistically clear and is now
predominantly user-space. The cumulative `-15.50%` result is therefore an
official result for the shared-translation mechanism stack, not a claim that
the shipped default path improved by the same amount.

Both maintained artifacts are complete and accepted:

- [`scripts/perf/evidence/native-cumulative-shared-prestack-current-battery-b0ddf87d.json`](scripts/perf/evidence/native-cumulative-shared-prestack-current-battery-b0ddf87d.json)
  (SHA-256
  `7e29dd76d856056f70f828c294431f517f88b9cff49cff6af92aacf5b9795f22`);
- [`scripts/perf/evidence/native-default-shared-gap-battery-b0ddf87d.json`](scripts/perf/evidence/native-default-shared-gap-battery-b0ddf87d.json)
  (SHA-256
  `3cb40488e9e744f525bc0dd51641ef2ba8cee07d62675e433f34c666053abb96`).

Each campaign contains eight quads plus excluded warmups and nine preflight
receipts. All preflights record the user's explicit battery authorization,
exact `Battery Power`, no thermal or performance warning, no foreign workload,
and no Docker oracle. Both arms use the exact arm64 platform manifest
`sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.
Docker's reset removed the old multi-platform index alias
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`;
the selected manifest, config, and layer blobs were rehydrated byte-for-byte
from Carrick's cache, so the workload bytes did not drift. The cumulative
artifact leaves `decision.retained=false` only because the statistics harness
cannot self-certify the already-passed external mechanism and correctness
gates. The gap artifact's `statistical_pass=false` correctly means the selected
shared candidate regressed; it does not make the accepted comparison invalid.

The maintained low-overhead syscall CPU tracer
(`scripts/dtrace/native-syscall-cpu-directional.d` plus
`scripts/perf/native_syscall_cpu_directional.py`) completed exact default and
shared captures with zero DTrace drops. It attributed nearly the entire shared
syscall-CPU delta to `read(2)`, and caller tracing resolved the largest reads to
`ContainerCacheAuthority::load_unit`. This led to keyed dylib identity and then
to the remaining manifest owner.

A preserved real Go-build cache and the reusable
`native_manifest_census` example now show that the remaining representation is
not marginal. The six-line ignored receipt is
`target/perf/native-manifest-census-20260731n1.jsonl` (SHA-256
`8600538f0e48f689670e09b786af0c42be3fecd0c4c53c06fe6f0ed722d6b0cc`):

- the largest units have manifests of `129.8`, `87.2`, `63.5`, and `54.6` MB
  beside only `6–15` MiB of translated code;
- block runtime metadata owns `99.5–99.6%` of the large manifests, while direct
  binding records and relocations together own less than `0.5%`;
- the largest unit contains `3,708,221` PC-map entries and `3,456,821` recovery
  entries; and
- those recovery entries reduce to `454,986` contiguous same-action runs, a
  `7.6x` count reduction before any PC-map compaction.

The attempted manifest-backed direct-binding record indirection was rejected
and removed: two adjacent controlled pairs put it about `+2–3%` slower. It is
not part of the retained tree.

Run-encoded recovery metadata is now implemented and retained default-on, with
`CARRICK_DSR_SHARED_RECOVERY_RUNS=0` as the exact entry-wire opt-out. The wire
rejects zero-length and overflowing runs, runtime fault lookup binds one action
without eagerly expanding the map, and the benchmark/DTrace target can select
either representation. The immutable same-binary eight-quad ABBA is published
as
[`scripts/perf/evidence/native-recovery-runs-abba-47457f44.json`](scripts/perf/evidence/native-recovery-runs-abba-47457f44.json)
(SHA-256
`13320af91b2870e1dfe0b08b250fc44723a35d96b5035a8dad234a5f5fbcab70`).
Runs won all eight quads: total CPU ratio `0.91519` (`-8.48%`, one-sided upper
`0.92377`, sign probability `1/256`), user CPU `-9.45%`, system CPU `-6.62%`,
outer wall `-8.30%`, and guest workload `-9.46%`. The artifact deliberately
leaves `decision.retained=false` because the statistical harness cannot
self-certify its external mechanism and correctness gates; those gates are now
satisfied by the bounded DTrace comparison and clean full repository gate.

The exact entries/runs DTrace pair completed naturally with no parser warnings.
Runs reduced total samples by `10.53%`, kernel samples by `9.02%`, user samples
by `11.85%`, and accounted syscall CPU from `6.220s` to `5.911s` (`-4.97%`).
The largest reductions were `read` (`-33.7%` CPU), `mprotect` (`-14.4%`), and
`write` (`-37.5%`). This is directional mechanism evidence rather than a
receipt-bound lossless profile; the ABBA result is the retention authority.
The comparison is
`target/perf/native-recovery-runs-syscall-cpu-comparison-47457f44.json`
(SHA-256
`7d2438ff1e4aa193bbc8180339516cad561540e8e110fd1722263ca406990696`).

The production `DSRPROF2` wall profiler is now load-bounded and live-proven on
the real shared-cache Go-build process tree. Run
`native-v2-go-shared-b0ddf87d-summary-6` completed naturally in `24.340217250s`
with `61,855` metric rows, zero incomplete pairs, zero remaining scoped
processes, every lifecycle/integrity/probe-error counter at zero, and zero
principal, aggregation, dynamic, dynamic-rinse, dynamic-dirty, or other drops.
The signed live binary SHA-256 is
`581ec7afec244e258b4cb35a7d4b7de5ae0681b9b4edfc68dd6649f3443692b7`;
the header binds base commit `b0ddf87d` and records the profiler-hardening tree
as dirty because the proof preceded this checkpoint commit.
The ignored raw receipt is
`target/perf/native-v2-go-shared-b0ddf87d-summary-6.raw` (`470,121` lines,
SHA-256 `37e2e940c8895f23c8a4129b28210f743e4892828082f5c98422134769083929`);
the accepted summary is the adjacent `.jsonl` file (SHA-256
`0648b12657b8a626e74c38ad024266ed5c2fa11c64ed10a2c471f36d1f6d9e7d`).
Offline exact replay through `__native-profile-validate` also accepted the raw
receipt.

The profiler now validates lifecycle state in the same DTrace clauses that
mutate it, checks libdtrace loss before parsing or symbolization, records
`dtrace:::ERROR`, right-censors terminal thread/process state, and emits
aggregated production rows instead of hot per-transition records. Exact fixture
replay still validates individual transitions. Its range model treats the
first ready marker as the activation frontier while allowing later shared
ranges to append and be inherited across fork; repeated ready markers reject.

PC-range attribution classified the `12,257` user samples as `53.13%`
host/unattributed, `33.30%` private translated code, and `13.58%` shared
translated code. That proves translated execution is material, but does **not**
yet prove the 3.7-million-entry PC map owns the next cost. Kernel samples are
directional only: the largest frames were DTrace itself
(`ml_set_interrupts_enabled_with_debug`, `dtrace_probe`), so they must not be
selected as runtime optimization targets. The next non-observer kernel owners
were `psynch_cvcontinue`, `thread_block_reason`, and
`kqueue_scan_continue`; they require a narrower low-perturbation experiment
before production coding.

Profiler-focused integration tests pass 10/10, exact raw replay passes, and the
complete `just test` gate passes, including the serialized runtime library at
1,128 passed with 5 ignored. The ordinary parallel `just ci` gate exposed an
unrelated pre-existing test-isolation defect in untouched
`carrick-signal-core`: one attempt lost process-pending signal 15 while another
attempt observed that same global signal in a sibling test. Both tests mutate
the process-global pending mask concurrently. The full controlled gate
`RUST_TEST_THREADS=1 just ci` passes; no signal production code or tests were
changed in this checkpoint.

The first ABBA attempt preserved a genuine 900-second, low-CPU timeout at
quad 4 B2 instead of rewriting it away. Candidate-only and exact ABBA reducers
then completed 32/32 and 18/18 runs, so it is retained as discovery evidence,
not attributed to run encoding. Commit `47457f44` adds
`carrick debug lldb-snapshot` and automatic pre-cleanup timeout snapshots to
the performance harness. A signed live three-process proof recovered nonempty
event rings and all-thread stacks before run-ID cleanup reached zero.

Verification is green: 252/252 `carrick-dsr-aarch64` tests, 35/35
`carrick-native-darwin` tests, 111 relevant Python harness tests, the serialized
runtime library at 1,128 passed with 5 ignored, and the complete `just ci` gate
on clean HEAD `47457f44`.
The full gate exposed four stale keyed-export fixtures and two eager-recovery
test helpers; both were corrected through the production validation key and a
single representation-neutral recovery lookup seam before the green rerun.

**Next:** use DTrace to split the remaining `+8.49%` shared-path user-CPU cost
into named host stacks versus translated execution with substantially less
observer work than the full wall profiler. Keep lifecycle/drop accounting and
symmetrically compare default/shared on the same signed binary. Use LLDB only
where unresolved PCs need a ground-truth image/offset mapping. Then implement
one red-first, default-on candidate with an exact opt-out and return it to the
primary eight-quad total-child-CPU gate. Synchronization/kqueue kernel frames
remain secondary until the user-space comparison is resolved; do not infer
that PC-map compaction wins from address classification alone.

Confidence that run encoding should stay is high (`~93%`) because statistical,
mechanism, correctness, and signed-live operability evidence now agree.
Confidence that the shared-translation campaign has a meaningful cumulative
win is now very high (`~98%`) because the direct result won all eight quads and
its upper interval remains well below parity. Confidence that the remaining
shared/default regression is real is also very high (`~97%`), and confidence
that `DSRPROF2` can reliably select the next owner remains high (`~95%`).
Confidence in reaching the full `>=30%` total-CPU goal is now moderate
(`~58%`): the direct stack result is `15.50%`, rather than the projected
`~21%`, leaving about 14.5 points that require a new measured owner. The
user-heavy shared/default delta and the `53.13%` host/unattributed user samples
make further progress likely, but neither yet proves a production fix.

---

## Current checkpoint — M2 lifecycle, raw-v2 parser, and launch identities

M2 now has an accepted process-owned translated-range catalog through the
first real shared-code consumer, checked post-fork replay, and atomic inherited
exec retirement plus post-success activation/publication/install handoff. This
is an observability/correctness milestone, not a performance result.

The retained signed binary is
`403b12878e36412943c0c5b79ba2271d11b0afbf77f2036afafa2211e610d69f`.
Strict codesign and `__DATA,__dof_carrick` verification passed. The shared
install path now:

- derives a stable typed unit identity and exact PC-map guest ownership;
- prepares catalog, block/index, direct-binding, dependency, retention, and
  executable-range state without logical mutation on recoverable failure;
- emits the shared catalog record first and release-publishes executable
  authority last;
- distinguishes block-start ownership from converging sensitive-terminal
  ownership; and
- has an actual-path regression test proving catalog event, complete logical
  install under the old executable head, then head publication.

The maintained
[`scripts/dtrace/native-translated-range-catalog.d`](scripts/dtrace/native-translated-range-catalog.d)
now fails closed over:

```text
shared-range announcement
  -> post-commit kind-12 unit-loaded
  -> PROFILE-only gateway entry inside that exact half-open range
```

It keys state by PID incarnation, keeps retained identities/addresses/epochs
at explicit 64-bit width, separates commit failures from optional run-witness
failures, and records root status, DTrace drops/errors, and every violation in
its schema-2 summary.

Accepted live receipts:

| mode | run ID | result | trace SHA-256 |
|---|---|---|---|
| semantic, profile absent | `m2-shared-commit-proof-019fb496-20260731i` | 2 announcements, 2 matched unit loads, `commit_ok=1`, `run_ok=0`, zero commit violations/drops/errors, clean exit and cleanup | `734124bf58941cd3d544d3d313fd8c823f4825a7bea76a0e2216f438a5f97cde` |
| trace-only, profile enabled | `m2-shared-run-proof-019fb496-20260731j` | 2 announcements, 2 unit loads, 2 in-range gateway entries, `commit_ok=1`, `run_ok=1`, every violation/pending/drop/error counter zero, clean exit and cleanup | `9d2868d56e29566071c17932bf43c9ead97f7b5575fc28cd77a2d544000a235d` |

The profile-enabled final child independently reported
`shared_unit_loads=2`, `shared_blocks_mapped=1168`, and
`shared_translations_avoided=2`.

Preserve the rejected precursor
`m2-shared-commit-proof-019fb496-20260731g`: it said `commit_ok=1` but exposed
DTrace dynamic-array truncation (`0x10edbc380 -> 0xedbc380` and a unit ID to
its low 32 bits). Commit `0c13a7bf` corrected the complete retained scalar
path; only the later `...31i` and `...31j` receipts are accepted.

Fork replay landed as `488e569d`, with failure hardening in `c771e23a` and the
bounded real-COW supervisor cleanup in `b32bb6f6`. It now:

- validates the complete active catalog and ready frontier before emission;
- advances the epoch with checked failure propagation;
- replays reset/private/shared/ready under the process writer and re-keys
  retained shared events for grandchild forks;
- clears the thread cache only after process replay succeeds; and
- aborts the open runtime resume service exactly once before any rebuild,
  fork-post, syscall-completion, stack-mutation, or guest-resume event on
  failure.

Focused catalog, fork, runtime failure, full DSR library, and serialized native
Darwin tests passed. Two independent review passes closed the bounded-wait,
child-allocation, inherited-frontier, runtime-event, and fork-failure FD
findings.

Atomic exec retirement landed as `44c3bd6c`, with authority/lifetime hardening
in `a6b1d9d6` and final preflight/supervision boundaries in `5889fa17`. It now:

- validates token identity, exact registry-owned private-JIT leases, and the
  optional active catalog before mapped-memory PONR;
- retains the process writer and exact surviving-thread borrow through PONR;
- consumes the token, commits optional catalog dormancy, and tears down
  bindings/cache/shared state without a post-PONR `Result` or assertion;
- resets the catalog only when pointer equality proves translator reuse, while
  a fresh replacement remains dormant and cannot inherit retiring-epoch
  overflow;
- reserves both thread-generation advances before PONR; and
- composes actual child repair and inherited exec as catalog epochs
  `1 -> 2 -> 3` under bounded, contained fork supervision.

The final independent re-reviews are clean. Focused reset tests passed 11/11,
the DSR library passed 238/238, the serialized runtime library passed 1,123
with 5 ignored, `just test` passed, and check/clippy/fmt/domain/diff gates
passed. Controller reruns of the `MAX-1` and composed fork/exec regressions
also passed.

Post-success exec handoff landed as `9767b954`, with production completion
ordering in `669a61d5` and final installation/wire preflight in `874b3a35`. It
now:

- prepares every fallible thread installation before catalog activation or
  image publication, retaining the exact selected process and checked epoch;
- activates the selected catalog, publishes host base/catalog, guest image,
  and host JIT identity, then commits translator installation without a
  recoverable `Result`;
- pre-serializes exact NUL-terminated host/catalog/guest USDT wire buffers
  before mapped-memory PONR, avoiding `usdt` JSON/string allocation while
  firing the post-success probes;
- delays self-reexec reset-end, ptrace exec-stop, snapshot/TLS state, and
  service completion until after translator installation; and
- proves real production activation and installation failures leave the
  replacement dormant, emit no image metadata, close exactly one RAII
  `Aborted`, and never resume the replacement image.

The first independent review found early self-reexec completion and
helper-only failure coverage. The second found stale metadata on fallible
install and hidden `usdt` serialization allocations. Both were repaired
red-first; final contract and adversarial re-reviews are clean. Final gates
passed 333 serialized native Darwin tests with 5 ignored, 28 observability
tests, translated-range 18/18, shared-unit 7/7, the checked handoff-epoch
test, `just test`, `just test-integration`, check, clippy, formatting, domain
lint, and diff checks. Controller reruns of the production failure, checked
epoch, and exact wire-buffer tests passed.

Signed live fork/exec tracing is now accepted at `e85e8a3b`. The immutable arm
is `target/native-m2-lifecycle-arm-e85e8a3b` (binary SHA-256
`ea89a1e0b3dda72dda2f456423ecb83dcfefcd91d14b059e6fb296e3d3c4b730`,
Mach-O UUID `E72707BE-CD27-3929-BF17-6B58BFF8A2C4`) against canonical arm64
image digest
`sha256:6199806814040f05f24d1845b3198f82a2bb982d336ffb04aa4470861cb214d6`.
The receipt-bound proof is retained under
`target/perf/native-m2-lifecycle-proof-e85e8a3b-a/`:

- run ID `native-m2-lifecycle-3fd5d09a-47fb-4158-bb47-62433720e0c9`;
- capture schema `carrick.native-m2-lifecycle-capture.v4`, accepted closure
  `dfdee66d8bdb0d620cd806f31d4e6ff7c17c4dde99bad03726ef1cb4b6204fdf`;
- raw trace SHA-256
  `66000405b7d79c2aca1cbc832f0bc2b3ae7ab61c18c0c639bd057551aa9e525b`;
- 30 exact wire-ordered milestones from the typed phase-27 launcher handshake
  through root exit, including host child PID `50561`, namespace PID `2`, and
  a positive namespace-domain `wait4` reap;
- `lifecycle_ok=1`, both stdout markers exactly once and ordered, and every
  violation, pending, DTrace drop, and DTrace error counter zero; and
- one successful run-ID-scoped cleanup with an empty final census.

The maintained parser now accepts cross-CPU transport reordering only through
a complete unique wire-ordinal set. It binds the guest namespace PID from
native fork phase 104 before `libc::fork`, treats the launcher readiness probe
as an exact once-only pre-root milestone, and uses a 50,000-iteration reducer
that completes inside the maintained 30-second DTrace bound. Focused gates
passed 59 lifecycle tests, 61 ABBA tests, Python compilation, formatting, and
diff checks; the live receipt was independently reloaded and revalidated.

Commit `c035f89a` adds the first `DSRPROF2` implementation slice. A hidden
`__native-profile-validate` harness and its shared parser implementation now
fail closed
over typed `(pid, start_sec, start_usec, image_generation, runtime_epoch)`
identity, exact fork frontiers, fresh-epoch child replay, failed and successful
exec, contiguous private/shared range catalogs, balanced kernel transitions,
latched off-CPU episodes, exact stack blocks, and natural process-tree
completion. The literal target/child fixture passes; more than thirty isolated
birth, frontier, replay, range, exec, kernel, off-CPU, delimiter, drop, and
completion corruptions reject. Existing `DSRPROF1` parsing remains unchanged.
Focused integration and unit suites, warnings-denied clippy, formatting,
typed-domain lint, and diff checks passed.

At that checkpoint this was structural validation rather than a gating-eligible
v2 profile. Commit `edbdc530` has since closed the production-emission slice:
the launch path renders `native-wall.d` from accepted birth and terminal
qualifications, binds the OS/program/qualification receipt hashes into header
authority, and emits birth-keyed `DSRPROF2` lifecycle, range, kernel, off-CPU,
and exact stack records. The ordinary summary and symbol overlay are published
only after the shared parser accepts complete state and every libdtrace loss
class, including split dynamic rinse and dirty drops. The valid fixture and
adversarial header/lifecycle/range/kernel/off-CPU/completion/drop/symbol tests
pass. The load-bounded hardening and signed Go-build proof described above now
close the remaining live-capture gate.

Commit `51e20831` adds the first live launch-qualification slice. The approved
design assumed Darwin `proc` provider start fields could supply process birth
identity; live tracing disproved that assumption because every `pr_start`
field was zero. The retained implementation instead queries checked
`PROC_PIDTBSDINFO` tuples and publishes them through a typed USDT probe. The
query stays inside the probe's enabled closure, so ordinary untraced runs pay
no process-info syscall cost. The CLI root publishes before command-specific
work and a native fork child publishes immediately after its child guard,
before later post-fork DSR events.

Controlled hidden fixtures and strict `BIRTHQUAL1` / `TERMINALQUAL1` parsers
live-proved the replacement mechanism:

- birth run `native-birth-qualifier-dev-006` observed the exact parent tuple
  twice, the exact child tuple twice, one matching `proc:::create`, both natural
  exits, and zero timeouts or violations (raw SHA-256
  `5c7136a8873121add7da71755acaea75985e2d0f20db1e8c75ed72ebd9a469c5`);
- thread run `native-terminal-qualifier-thread-dev-003` identified
  `syscall::bsdthread_terminate` at `proc:::lwp-exit`, with three returning-call
  controls and zero violations (raw SHA-256
  `26ea1052117cecca53d1365681514bc2008f05b06ba4ab92a2c723fe1a7afc48`);
  and
- process run `native-terminal-qualifier-process-dev-002` identified
  `syscall::exit` at `proc:::exit`, with one returning-call control and zero
  violations (raw SHA-256
  `7c44f2482d11652dffec416424a2cd3963a769479e2acbc5fa87d15344c0d2ea`).

The parsers bind the D programs, raw files, normalized receipts, and Darwin OS
build. On build `26A5388g`, the structural birth receipt is
`95fe4186319da4383b83264fa7eea054f9019562ad7b59caa421eb18992b122d` and the
terminal receipt is
`e500c6bf4e131f724f04a2b9a0eec45337f5f170ba2a44525e4f4b7097ee1fd4`.
Those standalone qualifier receipts are not gating authorities by themselves:
the hidden offline validator supplies a zero-valued report for structural
replay. The accepted production capture above supplies and checks the actual
libdtrace drop/interruption report before admitting its victim summary. Full
host tests, integration tests, focused warnings-denied clippy, formatting,
domain lint, diff checks, and all three live DTrace fixtures passed.

The lifecycle receipt closes the catalog/fork/exec prerequisite, the raw
grammar and automatic launch authority exist, the required Darwin
birth/terminal mechanisms are live-qualified, and the immutable signed
real-workload `DSRPROF2` capture proves production emission and qualification
agree under the Go-build process tree. Use that capture, not the older PID-only
`DSRPROF1` stream, to rank the next translation/kernel owner.

**Next:** narrow the accepted birth-keyed PC-range evidence into one
low-perturbation host-user hypothesis that explains the directly measured
`+8.49%` shared user-CPU delta. Preserve lifecycle and DTrace loss authority,
resolve ambiguous PCs with LLDB where necessary, then advance one default-on
candidate with an exact opt-out to the primary ABBA total-child-CPU gate.

The `>=30%` CPU goal remains open. The combined shared-translation stack now
has a direct `-15.50%` total-CPU result; the next 14.5 points require a new
measured owner rather than compounding prior projections.

---

## Prior checkpoint — M1 authority closed, M2 performance work opened

**M1 instrument authority is complete, but it is not a speed result.** The
accepted same-binary control/control artifact is
[`scripts/perf/evidence/native-go-build-abba-control-control-v1.json`](scripts/perf/evidence/native-go-build-abba-control-control-v1.json)
(SHA-256
`13f53bfec091cbbdee53dd1cbd91e8bad061948989a004113fe8fb1c24171ee8`).
Its eight-quad total-child-CPU B/A median is `1.0052799282253981`, with
`statistical_pass=false` and `retained=false`. It validates receipt-bound ABBA
execution and the instrument's 2.5021% n=8 resolution; it does not update H0,
establish a regression, or claim an optimization.

**The load-coupled correctness defect discovered during closeout is fixed.**
The first retry-enabled broad smoke reported 21/23 and its two targeted retries
reported 2/2; preserve that sequence as discovery evidence, not as a rewritten
23/23 run. A real LLDB core then proved that translated execution still carried
control and address state through physical x18 even though Darwin may clear its
platform register asynchronously. Commit `5020e509` removes all such emitted
live ranges and adds fail-closed decoded-instruction, cold-arm, stack-pointer,
DC-ZVA, and every-recovery-boundary coverage.

The retained signed binary
`d31e60966075c3709ac3cd83a0fe4b4b6d672371ba2b6ff9e99ae6400d13c9e0`
passed the exact concurrent CPython `test_close_fds` reducer 4/4. A fresh
`just conformance-native smoke --workers 4 --flake-retries 1` then reported
23/23 MATCH, including `cpython-subprocess` 278/278; the oracle phase used all
23 cached results and ran Docker zero times. Final `just ci` passed.

**Next:** begin M2 with a fresh signed binary from this retained code state, an
untraced Go-build run, and DTrace/carrick-trace attribution. Keep the Go-build
workload as the primary retention gate, use controls that opt out of one
hypothesis at a time, and do not turn a trace sample into a performance claim.
The ≥30% CPU goal is still open.

---

## The goal

**Make carrick's translation pipeline pay for itself:** land container-lifetime
translation sharing as a net win, and cut non-guest work on the native/aarch64
go-build reference workload by ≥30% CPU.

| | |
|---|---|
| **Primary metric** | `cpu_median_s` on the go-build reference workload, as a paired ratio vs baseline `0686248a` |
| **Target** | ≤ 0.70 |
| **Protocol** | ABBA-ordered, ≥8 quads, `abbascreen.sh` + `abbastats.py` |

Ratio, not absolute: total CPU ranges 32–44 CPU-s run-to-run on the same binary.

### Workstream targets, and where the numbers stand

| gate | metric | start | target | now |
|---|---|---|---|---|
| A0 | `direct_resolver_exits`, sharing ON vs OFF | 779,874 → 135,259,579 (173x) | mechanism named + control arm | **0** |
| A1 | wall, sharing ON ÷ OFF | 3.2–4.2x | ≤ 1.0x | 1.268x |
| A2 | translations per build | 1,031,914 | ≤ 400,000 | 819,901 |
| A2 | shared-unit block coverage | 14.2% | ≥ 60% | 33.1% |
| B | emitted bytes per build | 599 MB | ≤ 400 MB | 553 MB |
| B | host-code share of on-CPU | 35.8% | ≤ 25% | not re-measured |
| C | kernel, non-syscall | 30.7% | ≤ 25% | unchanged |
| C | address-space faults | 2,204,683 | ≤ 1,500,000 | 2,098,739 |

**Primary metric today: ~1.0.** Sharing ships OFF, so the shipped path is
unchanged. Every number above is reproducible; none is final.

---

## What was attempted, and what each attempt measured

### A0 — root-cause the exit amplification → **met**

Classified every `ResolveDirect` by whether the source PC falls *inside* a
shared block's `[start, end)` range — not equality against block-start keys, the
mistake that forced a retraction in run 6. Result: 99.4% of amplified exits are
private→shared, across 74,726 distinct edges at ~1,822 traversals each,
confirmed by a control arm shipped in the same commit.

### A1 — stop being a regression

Five constructions, in order.

**1–4: install the unit's binding table at gateway ENTRY.** Each removed the
amplification (135,715,237 → 0 / 48 / 44) and each faulted. Attributing the
fault (run 22) explained all four at once: a context holds ONE
`generation_bindings` pointer while a private context reaches blocks from N
units, so the guard indexes the wrong unit's table as soon as a second unit is
touched. The wandering fault address (`0x20`, `0x60`, `0`) was that, not one bug
relocating. All four reverted.

**5: install at the EDGE** — `b23503ea`, landed. Each private→shared edge is
patched to a six-word trampoline (`movz`/`movk` chain, `str x17, [x28,
#CTX_GENERATION_BINDINGS]`, `b`) built from the per-block
`SharedBlockAuthority::generation_bindings` pointer already available at patch
time. An edge statically knows its target's unit; entry-time install never can.
Amplification 135,715,237 → **0**, and the workload completes with sharing ON
for the first time. A1: 3.2–4.2x → **1.114x**.

The coverage work below then moved A1 to **1.268x**.

### A2 — raise coverage

Measured that fused blocks were excluded from shared units
(`block.extensions.is_empty()`), worth 2.2x of coverage: 14.4% with fusion on
vs 32.1% with it off (run 26). Fusion is a shipped win (76% fewer gateway
exits), so disabling it is not the trade — it also raises translations 22%.

**Made fusion and sharing work together** — `7781d97e`, landed. The exclusion's
premise held: superblock formation extends only along the fall-through and stops
at `page_end`, so a fused plan is contiguous and single-page and the template key
already spans it. Removing it exposed two consume-side defects, one **latent
since before fusion** — sensitive-exit metadata was keyed by block START while
the lookup is by the SENSITIVE instruction's PC, which differ for any block
longer than one instruction.

Coverage 14.4% → **33.1%**; translations 1,045,248 → **819,901** (−21.6%).

**The paired ratio moved the wrong way**: 1.106 → 1.235 CPU, 0/8 quads, sd 1.4%.
This is the campaign's most important open result — on this workload, cutting
fresh translations by a fifth did not buy CPU, and the reason is not yet
established. See *Open questions* #1; the leaf profile currently cannot see the
likeliest mechanism.

### B — per-translation host cost

Narrow guest-PC materialization (`3d480e88`) cut emitted bytes 610.0 → 553.3 MB
(−9.3%), mechanism gate confirmed. Paired CPU effect: zero. Extrapolated to B's
full 400 MB target that is ~0.9%, which raises the question of whether emitted
bytes are the right proxy for the CPU they were chosen to represent.

### C — kernel fault term

Baselined (2,098,739 `as_fault`, 82% zero-fill, 50 processes, flat at
31–39k each) and three candidates probed:

| candidate | result |
|---|---|
| scavenger decommit (`madvise`) | 328 calls vs 1,716,964 zfod — 1:5000, not the mechanism |
| per-process address-space setup | ~2,000 faults/process trivial vs ~34,000/process build — not startup |
| sub-page `PROT_NONE` amplifier | **real**: any 16 KB host page whose four 4 KB guest sub-pages disagree on protection maps `PROT_NONE`, so every access faults, not just the first. Bounds to ~382,000 faults = 18% of the term |
| the zero-fill majority (82%) | **open** |

---

## What landed (all gated, all on `main`)

| commit | change |
|---|---|
| `b23503ea` | private→shared edges patch through a binding-install trampoline (A0) |
| `7781d97e` | fused superblocks shareable + sensitive-metadata keying fix |
| `3d480e88` | narrow guest-PC materialization (−9.3% emitted) |
| `5f9cedfb` | `--variant shared` — sharing without the artifact spike |
| `602df3af` | per-thread block cache (`lock_shared_slow` 8.2% → 4.0%) |
| `0e969f07` | hardware SHA-256 (0.55 → 2.20 GB/s; 1.99% → 0.40% in-profile) |
| `22394916` | frame pointers enforced workspace-wide + `just ci` check |
| `7c701293` | CPU-seconds in the perf runner |
| `0686248a` | JIT-aware profiler |

**Guardrails:** `baseline.jsonl` and `baseline.native-dsr.jsonl` unchanged
across all 33 commits; `just ci` green at tip (36 suites, zero failures).
Sharing remains off by default, so shipped behaviour is unchanged.

---

## Open questions, ranked

1. **Why did −21.6% translations cost CPU?** Leading hypothesis is execution
   locality: 400,000+ blocks across 54 separately `dlopen`ed unit mappings
   replacing a compact bump-allocated private cache. **Blocked on tooling** —
   the JIT-aware profiler classifies a PC by the PRIVATE cache bounds, so
   unit-mapped code is misfiled as `host` and the arms' bucket totals are not
   comparable across a sharing boundary (run 24). `shared_guest_ranges` already
   tracks what the classifier needs. Fix that first; it gates the question.

2. **The zero-fill majority of the fault term** (82%, 1.72 M). `vminfo` carries
   no fault address, which is why all three probes so far were indirect. Needs
   distinct-address accounting — `fbt::vm_fault:entry`, or a guest-side census
   of pages touched. Peak-RSS sampling gave median 91 MB/process against the
   531 MB the fault count implies, but 0.3 s sampling of 1–2 s processes is not
   evidence.

3. **The sub-page `PROT_NONE` amplifier** is real and independent of everything
   above — worth fixing on its own terms. Sized at 18% of the fault term and
   under the goal's 5%-of-CPU chase threshold, so it will not move the headline
   alone.

4. **Re-screen the earlier rejections.** The instrument is now ~4x sharper (ABBA
   + CPU resolves ≥0.8–1.1% at n=8, vs ~3.2% for the wall screens that produced
   them). The whole-generation-guard arm measured 0.9867 (p=0.38) — unmeasurable
   then, resolvable now. The goal placed codegen cycle quality out of scope;
   revisit that scoping before spending on it.

5. **A2's remaining coverage gap** (33.1% vs ≥60%). Each unit load serves ~2,930
   blocks where a process translates ~26,707. Why an artifact covers ~11% of one
   process's needs is unmeasured — narrow capture, a cap, or a keying mismatch.

---

## Instrument and traps

- **Use `abbascreen.sh` / `abbavariant.sh` + `abbastats.py`.** A null screen
  measured a ~1% penalty on whichever arm runs SECOND; ABBA cancels it inside
  each quad. Report CPU-seconds, not wall: sd 1.4–1.8% vs 4.3–5.5%.
- **One unpaired run is not an instrument.** A single JIT-aware profile put the
  ON arm faster while 8 ABBA quads said 1.235x slower. The screen governs — and
  the temptation is always to quote whichever number flatters the change.
- **Check the arm actually contains your change.** The first A1 screen used
  `--variant candidate`, which also enables `CARRICK_DSR_ARTIFACT_SPIKE=1`;
  neither the fix nor the gate's baseline involves it, so the result was void.
  `--variant shared` is the gate's configuration.
- **`native_go_build.py` refuses a dirty worktree.** Commit harness edits before
  measuring — that guard turned a void run into an obvious crash rather than a
  plausible-looking ratio.
- **`sudo dtrace` needs a foreground call.** Detached/`nohup` runs lose the
  credential silently while the workload still succeeds, yielding an empty
  profile. Give D scripts a `tick-Ns { exit(0); }` so they self-terminate;
  killing the `sudo` pid leaves dtrace running and hangs the harness.
- **Attribute before building.** Four hypotheses in A1 and three in C died on
  first contact with a counter. Two could have been refuted by arithmetic alone
  — 817 M extra instructions is ~0.2 CPU-s, not the 3.2 being explained.
- Stamp `CARRICK_RUN_ID` and reap with `scripts/sudo/kill.sh <run-id>`; never
  `pkill -f carrick`.
