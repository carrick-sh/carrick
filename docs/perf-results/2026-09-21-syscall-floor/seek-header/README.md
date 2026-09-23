# Seek-header experiment rejected; completed inotify09 population qualified

This candidate does not improve original inotify09. Four measured process runs
per signed arm give median **21.90 s before, 21.95 s after** (+0.23%). All runs
pass and finish by the LTP execution-loop limit. The product edit, active test
module and experimental contract were removed; the exact measured baseline
executable was restored before the diagnostic-profile addition below. The patch
and red/green evidence are retained here.

The crucial correction is path reachability: a completed original-workload trace
counts **3,000,000 add-watch and 3,000,000 remove-watch host-service calls, but only
one host-service lseek**. Optimizing that lseek handler cannot remove repeated
work in this workload. Choosing the handler before qualifying its live
population was an investigation error. The serial contract-scale reducer was
also initially described incorrectly as concurrent; its source and live counts
are preserved to make the correction explicit.

## Candidate and contract evidence

The experiment replaced three heap-backed guest-memory reads of the lseek
identity-page seek header (4 + 4 + 8 bytes) with one checked read into a 20-byte
stack buffer. Gate, matching fd, nonnegative offset, fallback and offset
publication semantics remained in the same handler. The existing write handler
already used an analogous stack read.

The candidate contract kernel.fs.seek-header-input was tested through the real
kernel dispatcher at scales 1/8/32/128. The red executable observed 3/24/96/384
metadata-input allocations; all four scale observations were emitted before the
budget failure. The candidate observed zero and one 20-byte read per request.
The semantic test covered inactive and invalid gates, matching/mismatched fd,
negative offset and read failure. Five focused seek tests passed after the
change, including existing shared-offset coverage.

These counters measure only the seek-header input, not all syscall allocation.
They establish a local structural improvement, not a workload improvement.
The rejected patch includes the contract and test source for replay; neither
remains registered in the active source tree. An initial test-module path build
failure is retained in setup-module-failure.log.

## Original LTP result

Same pinned ARM64 LTP image, shell entrypoint, fs=host, unlimited trap count.
One warmup per arm was declared before the eight measured runs, in ABBA then
BAAB order. No tracing, builds or Docker guest overlapped Carrick timings.
The external 40-second bound was unchanged and was never reached.

| Order | Arm | Elapsed seconds |
| --- | --- | ---: |
| warmup | baseline | 21.88 |
| warmup | candidate | 22.39 |
| 0 | baseline | 21.69 |
| 1 | candidate | 21.91 |
| 2 | candidate | 21.80 |
| 3 | baseline | 21.80 |
| 4 | candidate | 22.13 |
| 5 | baseline | 22.00 |
| 6 | baseline | 22.03 |
| 7 | candidate | 21.99 |

Three fresh native ARM64 Docker runs followed the Carrick phase:
5.76, 5.68 and 5.90 seconds; median **5.76 s**. The raw baseline/Linux ratio is
**3.80x**; candidate/Linux is **3.81x**. No I/O adjustment is applied.

Candidate minus baseline differences in the four adjacent A/B pairs are
+0.22, 0.00, +0.13 and -0.04 seconds. This small diagnostic sample supports no
speedup claim and does not establish statistical equivalence. /usr/bin/time
reports hundredths of a second; core placement was uncontrolled. LTP's adaptive
synchronization and spin work can differ even when the loop limit is identical.
All raw process results are retained; internal benchmark samples are not
treated as independent process replications.

## Completed host-service census

The durable scripts/dtrace/hvpatch-inotify09-completed-population.d uses
carrick trace --require-script-exit, follows the root and its descendants,
and rejects non-firing, DTrace errors and missing root completion. The CLI
checks dropped records. The baseline trace exited normally with seen=1,
errors=0, root_exited=1; original LTP reported TPASS and Exceeded execution loops.

| AArch64 syscall | service begin | arguments | service end |
| --- | ---: | ---: | ---: |
| inotify_add_watch (27) | 3,000,000 | 3,000,000 | 3,000,000 |
| inotify_rm_watch (28) | 3,000,000 | 3,000,000 | 3,000,000 |
| lseek (62) | 1 | 1 | 1 |
| write (64) | 32 | 32 | 32 |
| clock_gettime (113) | 1 | 1 | 1 |

Every other observed syscall also reconciles begin/arguments/end in the raw
capture. These are **kernel host-service events**, not every guest SVC or every
HVF exit. Existing EL1/engine fast paths can bypass these service probes.
In particular, the low write/seek counts do not mean that the writer does no
I/O, incurs no cost, or lies off the workload's critical dependency.

Both arms also passed the smaller serial contract-scale 128 trace with identical
counts: 128 adds, 128 removes, one host-service lseek and four writes. That fixture
does not reproduce the original two-thread synchronization; it cannot qualify
the candidate as a repeated host-seek optimization.

The CLI --json report from the full LTP command contains 59 traps and 50 syscall
invocations for the shell wrapper context. Those numbers are retained in the
raw records and **must not be used as the full-workload population**.

The full trace uses three USDT aggregations per serviced syscall and is highly
perturbing. It supplies counts/completion, never uninstrumented timing. The
measured script is archived as receipts/measured-population.d; the durable
script was subsequently registered as a Rust profile with a digest header;
its header documents the qualified counts and blind spots.
Only the baseline full run was traced. Candidate timing and small-fixture
populations are separate evidence, not a claimed candidate full-run census.

## Watch-only controls

Two independent invocations per arm; 21 internal samples per cell. Entries are
medians of process medians, nanoseconds per pair. These loops contain no timed
write/seek and do not exercise the candidate handler.

| Control | Baseline | Candidate | ARM64 Linux |
| --- | ---: | ---: | ---: |
| Invalid add/remove | 3183 | 3196.5 | 255 |
| Two unchanged adds | 3662.5 | 3681.5 | 551.5 |
| Initially empty batch, 128 pairs | 3436.5 | 3290.5 | 1226.5 |
| Growing queue, 8192 pairs | 3558 | 3516 | 866 |
| Overflowed queue, 65536 pairs | 3547 | 3524.5 | 914.5 |

Small changes in these negative controls do not qualify a seek optimization.
The invalid-pair baseline is still 12.48x Linux: performance promotion remains
open/red, irrespective of semantic success.

## Same-source I/O controls, kept separate

Fresh native macOS and static ARM64 Linux executables were built from the same
scripts/perf/io-floor.c. Each process performs nine timed samples of 32,768
iterations per operation after warmup. There are two macOS, two Linux-local,
two Linux-bind and two Carrick invocations per signed arm. Carrick and native
macOS use the same host directory; Linux-bind uses that directory through Docker.
Every process verifies 64-byte contents, length, shared offset and removal.

Nanoseconds per iteration, median of process medians:

| Operation | Native macOS | Carrick baseline | Candidate | Linux-local | Docker host bind |
| --- | ---: | ---: | ---: | ---: | ---: |
| seek | 216 | 21 | 21 | 124 | 132 |
| pwrite 64 bytes | 980 | 3319 | 3349 | 326 | 12757 |
| write 64 bytes + seek | 1225 | 2301 | 2298 | 449 | 13001 |
| valid-fd fstat | 239 | 2016 | 2038 | 161 | 162 |

This is hot-inode buffered I/O, with no fsync or durability claim. Carrick's
~21 ns seek uses an existing fast path; it is not the host lseek handler cost.
The direct host-file write+seek control retains its advantage over Docker-bind
(about 5.65x faster here), while still costing about 1.88x native macOS.
No component cost or corrected inotify09 runtime is inferred by subtracting
these medians. Native platform I/O differences remain separately visible.

## Artifacts, restoration and remaining scope

Source HEAD: 9bb2392396b8531e93f5262657bf3aa9c5767488 plus the preexisting campaign
working changes. Host: Apple M4, macOS 27.2 build 26B5086k. Image:
localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b.
LTP reports version 20260529.

- Baseline CLI SHA256: dcb0e51088f176b8e28dc71bc004b2d1dd024bd35fcdc8cbf563f50f47ac2955
- Candidate CLI SHA256: ec641d2c438fa42957cc30b464de92adc47ea3b458954ccc76c1c9a3bd71fd11

Both were freshly linked and codesigned through just build. artifacts.json
contains CDHash, LC_UUID, hypervisor entitlement and __dof_carrick. The earlier
transport-control CLI c3fb9fd... remains unchanged but is not the baseline for
this trial. Both frozen seek artifacts remain under target/lease-cost/seek-header.

The source-before archive/hash map, isolated rejected patch, exact commands,
raw streams, failures and cleanup receipts are retained. The restoration audit
checks all recorded preexisting source files byte-for-byte and checks that the
release executable matches the measured baseline. All 32 unique guest/control/
trace invocations completed with no scoped survivors. No unrelated source
change was reverted. The final CLI adds only the diagnostic trace profile described below; its
signed identity is distinct from both timed arms. No commit or push was made.

This experiment deliberately stops short of signed promotion: the candidate
was rejected and removed. The focused kernel tests and original signed workload
runs do not replace the signed embed/probe/smoke/full/CI gates, which were not
run for this candidate. No new timing contract acceptance is claimed.

## Next decision

Do not choose another lseek leaf optimization for original inotify09 without a
live full-workload population demonstrating that it is repeated. Qualify the
exact path before implementing an optimization.

Six million watch service calls make shared syscall handling a relevant target;
their count alone does not prove it is the longest pole. The earlier mailbox
versus register-control intervention did move original completion time by about
10%, and that benefit is already present. The larger open experiment remains a
same-thread native/DSR execution path retaining the current kernel contract,
followed by the original workload. Code publication/revocation is enabling work,
not a speedup, and native research-runner gains are not product acceptance.

Before further expansion, require either a concrete common-path intervention
that moves original untraced completion or an actual native execution slice
that can be subjected to the same test. Repeating register-read, idle-signal,
watch-registry or compute-emitter tuning already measured elsewhere is not new
evidence. Preserve writer semantics, synchronization and Linux comparison;
no no-op watch handler, eliminated I/O or serialized test can count as a win.

The near-1x goal remains unachieved. This turn contributed a rejected experiment
and a validated full-workload census, not a new product performance improvement.


## Durable Rust trace profile and final validation

The retained implementation is
`carrick trace --profile hvpatch-inotify09-population --trace-out FILE -- run …`.
The existing profile enum/renderer/capture path bundles and hashes the D program.
A strict Rust reader requires the current digest, a completed root with nonzero
firing and no errors, unique positive canonical count rows, equal begin/args/end
populations for every syscall, overflow-safe totals, and exactly3M services for
each watch call. The existing consumer report must also show no drops or
interruption and an observed successful DTrace exit. Raw capture is mandatory.
This profile is specific to the pinned LTP population, not arbitrary inotify
tests. A matching population is not a semantic verdict; inspect TPASS separately.

The new CLI integration check failed red because the old CLI did not expose the
profile. Final `cargo test --release -p carrick-cli --test trace_profile` passes
all26 tests, including the real full-run count fixture and16 malformed/incomplete
variants. The suite already runs in the project recipes; no unexecuted in-file
test module was added.

Scoped `cargo clippy --release -p carrick-cli --bin carrick --test trace_profile
--no-deps -- -D warnings` passes. The broader invocation fails on six preexisting
manual_is_multiple_of diagnostics in carrick-aarch64's anonymous_discard.rs and
engine.rs. Both source hashes still match the pre-experiment snapshot; those
diagnostics were not suppressed or edited. Full CI and signed promotion remain
uncompleted.

The final `just build` artifact is SHA256
1142bb6dc6202ab3675dc6485b4f479e1d9425b2b75a293c948aef5e65db8918.
Its exact signed copy ran the original inotify09 through the new profile:
TPASS, execution-loop limit,55 fully reconciled syscall numbers,3M add-watch,
3M remove-watch, one host-service seek. Scoped cleanup found zero survivors.
The live program digest is
5c9089df891d028a55357d461eb7fd2be994bf80557d58a9bd98d6aae15a47bb.
This is an additional validation run, separate from the32 original experiment
invocations. It supplies no new uninstrumented timing claim.

The final release CLI contains this diagnostic addition; guest execution,
dispatch and watch behavior match the restored baseline source. Exactly four
preexisting CLI/test files differ from the3041-file snapshot, plus the new
reader, fixture, D script and documentation. The earlier restoration audit
records the point before this deliberate addition. See trace-profile-audit.json,
trace-profile.patch and receipts/trace-profile/ for commands, tests, lint
failure, signed identity, live raw output and cleanup.
