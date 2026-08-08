# Tier D Node and Python Default-Path Design

**Status:** approved for execution 2026-08-07 by the active goal continuation.
**Scope:** Darwin/AArch64, `--exec-backend native`, native16k, unmodified
Linux/AArch64 PIE executables. Tier D becomes the shipped default for eligible
images only after the correctness gates below pass. ET_EXEC images remain Tier
T because Darwin's 4 GiB hard page-zero makes their low fixed addresses
unmappable.

## 1. Goal

Finish Tier D as Carrick's default execution tier for eligible PIE images, make
the canonical Node and CPython workloads correct under that default, and reduce
their clean end-to-end workload wall toward no more than 2.0x native-arm64
Docker, with 1.0x as the stretch target.

This is one product goal with two required gates:

1. **Correctness:** eligible images enter and remain in Tier D without unnamed
   crashes, silent fallback, semantic divergence, or an unimplemented mid-run
   leave.
2. **Overhead:** once translation has been removed, attribute and reduce the
   remaining dispatch, VFS, exec, memory, and Darwin-kernel amplification on
   the same pinned Node and CPython workloads.

The goal does not close at "Tier D is faster" or at a smaller intermediate
ratio. If a controlled campaign remains above 2.0x, the measured residual
selects the next campaign item and this goal remains active.

## 2. Current evidence

The current-HEAD baseline was taken at `3e88dd8a95940fc8467d4f58c7bb30e1a1b1c47f`
with signed binary SHA-256
`287faa2572ce0671a982be8623e30c35f0ac0603527a4002a8b5b1dcf202be8a`.
Carrick cases ran serially and Docker results came from the committed oracle
cache; Carrick and Docker did not overlap.

| gate | current Tier-D-forced result | Docker ratio / failure |
|---|---|---|
| `node-app-smoke` | MATCH, Node itself refused Tier D | 19.68x |
| `node-v8-smoke` | MATCH, Node itself refused Tier D | 23.84x |
| `cpython-fcntl` | direct entry, then named leave | `BlockingRecordLock`, 11.59x |
| `cpython-glob` | MATCH, direct | 6.30x |
| `cpython-json` | MATCH, direct | 1.05x |
| `cpython-math` | MATCH, direct | 2.46x |
| `cpython-subprocess` | Empty | executable-window scan refusal |
| `cpython-threading` | Empty | executable-window scan refusal |

The earlier controlled ablation remains the mechanism proof: on the pinned
CPython fixture, Tier T was 4,097.9 ms / 22.1x Docker and Tier D was 1,484.4 ms
/ 8.0x Docker. Removing same-ISA translation therefore removed 63.8% of Tier
T wall (2.76x), but the post-translation residual is still the larger product
problem.

### 2.1 The first shared blocker is proven exactly

The current tier census identifies one word in both ecosystems:

- Node: `0x38764d52` at `0x1c44b84` in
  `/opt/node-src/v24/out/Release/node`.
- CPython: `0x38764d52` at file-window offset `0x281478` in stripped
  `/usr/lib/aarch64-linux-gnu/libcrypto.so.3`.

Both bytes are the ASCII substring `RMv8` in the same OpenSSL assembler banner,
placed after a `ret` in an executable `.text` section. The unstripped Node ELF
also proves the region is data with AArch64 mapping symbols: `$d` begins at
`0x1c44b70` and `$x` resumes at `0x1c44bc0`. The shipped libcrypto is stripped
and carries no static symbol table, so mapping symbols alone cannot solve both
cases.

The stronger proof does not depend on reachability or symbols. Interpreted as
the AArch64 load/store register-offset class, `0x38764d52` sets a fixed-reserved
encoding bit. The nearest allocated encoding, `0x38764952`, is
`ldrb w18, [x10, w22, uxtw]`; the rejected word differs in the fixed bit at
position 10. Therefore the rejected word is architecturally unallocated. If it
were executed, it would trap as an illegal instruction rather than read or
write x18. Leaving an independently proven unallocated encoding untouched is
safe whether the bytes are data or are reached as code.

This distinction is load-bearing: Tier D may accept an undecodable word that
an independent encoding-family proof classifies as unallocated. It may not
whitelist this word, assume all undecodable text is data, or treat a decoder
failure as proof of invalidity.

## 3. Architecture

### 3.1 Tier decision and rollback

Tier selection remains per-image at launch and every exec replacement. The
new default is:

- eligible PIE image: Tier D;
- fixed-low-address ET_EXEC or a named fail-closed eligibility refusal: Tier T
  before guest entry;
- exact host rollback hatch: `CARRICK_NATIVE_DIRECT=0`;
- `CARRICK_NATIVE_DIRECT=1` remains the force-on diagnostic during bring-up.

There is no silent mid-run fallback. Tier D and Tier T use different memory
identity and execution mechanisms; switching a live process after mappings,
threads, or JIT state exist is not a semantics-preserving operation. An
unimplemented executable transition continues to leave with a named reason
until that transition is supported.

### 3.2 Executable-word validity

The first implementation adds a small, separately tested AArch64 encoding
validity layer adjacent to `scan_executable_words`:

- `bad64` remains the operand authority for instructions it decodes;
- a decoder failure still runs the existing raw x18-field over-approximation;
- before refusing, a source-bound family validator may prove the raw word is
  architecturally unallocated;
- only a proven-unallocated word bypasses the x18 refusal and remains
  unmodified;
- a valid neighboring encoding that names x18 must still decode and pass
  through the existing veneer machinery.

Each accepted family requires a cited ARM encoding mask, fixed-bit tests, a
valid-neighbor mutation test, and a real corpus regression. This creates a
general mechanism without pretending to implement a second AArch64 decoder.
If later corpus gaps are data that are valid instruction encodings, mapping
symbols or a stronger code-range authority can be designed from that evidence;
they are not needed to weaken the present gate.

### 3.3 Correctness blocker ladder

After every blocker closes, rerun the exact focused workload and census before
choosing the next implementation. The expected ladder is:

1. **OpenSSL reserved encoding:** recover Node main-image entry and CPython
   extension/library loading with the validity proof above.
2. **Node executable transitions:** observe the first real V8/WebAssembly JIT
   mmap/mprotect shape after Node enters Tier D. Extend the existing Tier-D
   scan-and-patch window pipeline to that exact anonymous or shared executable
   transition, preserving Darwin MAP_JIT W^X and rescanning after every
   write-to-execute transition. Do not invent support before the live shape is
   captured.
3. **Blocking record locks:** after dispatch has released every subsystem
   lock, call the shared `drive_blocking_record_lock` helper on the calling
   Tier-D host thread, exactly as the native DSR loop does. Sibling guest
   threads are independent host pthreads and remain able to release the
   conflicting lock; success or `EINTR`/errno then returns through Tier D's
   normal syscall-boundary signal/restart semantics.
4. **Multithreaded fork:** quiesce sibling Tier-D threads before host fork,
   reset child-only thread/runtime state, and resume the parent only after the
   child state is coherent. Reuse the native DSR/HVF lifecycle contract rather
   than introducing a second process model.
5. **Remaining native smoke:** attribute and close the Ubuntu image-specific
   x18/loader fault and the Go PIE multithreaded signal tail exposed by the
   existing native smoke. The default cannot flip while another eligible image
   crashes merely because it is no longer Tier T.

Every step is red-first: the real current binary and a focused fixture must
demonstrate the named refusal or divergence before the fix is applied.

### 3.4 Default flip

The default flips only after all of these are true on the same signed tip:

- `node-app-smoke` and `node-v8-smoke` MATCH Docker and census the Node main
  image plus eligible children as direct;
- `cpython-fcntl`, `cpython-subprocess`, and `cpython-threading` MATCH Docker
  with no Tier-D leave;
- the complete `just conformance-native smoke` has no unexcused regression,
  crash, timeout, or eligible-image Tier-D failure;
- a control run with `CARRICK_NATIVE_DIRECT=0` remains byte-for-byte compatible
  with the pre-flip Tier-T behavior;
- `just ci` passes serialized as required by the repository.

The flip is its own narrow commit so the rollback and comparison boundary stay
obvious.

## 4. Canonical workload gates

Conformance-suite elapsed time includes wrapper and harness work and is useful
for regressions, not sufficient as the product scoreboard. The campaign uses
two digest-pinned direct workload fixtures.

### 4.1 CPython

Retain the ablation ladder's `ablation-pie-fixture-v2` workload and exact
CPython 3.12.13 image. It covers pure-interpreter compute, dictionary churn,
300 file cycles, four threads, and five subprocess execs, and prints one
deterministic `PY_OK` result. It already has a clean Docker anchor of 185.3 ms.

### 4.2 Node

Add a direct Node scoreboard that invokes the image's pinned Node 24 binary,
not the shell conformance wrapper, over both existing fixtures:

- `app-smoke.js`: crypto, filesystem, child process, TCP, worker thread, timer;
- `v8-smoke.js`: WebAssembly, atomics/shared memory, Intl, worker thread,
  allocation pressure.

The scoreboard reports the two fixture ratios separately and a declared
combined total; one fast fixture may not hide a slow one. Guest output remains
the existing deterministic `app-smoke ok` / `v8-smoke ok` contract. The image
reference, resolved digest, entrypoint, argv, fixture hashes, signed binary
hash/UUID, OS build, and host preflight receipt bind every accepted result.

### 4.3 Measurement protocol

- Carrick phase first, Docker phase second; never concurrent.
- Quiet-host preflight and unique `CARRICK_RUN_ID`; scoped reaping only.
- At least one warmup and five interleaved samples per Carrick arm; at least
  five Docker samples in its separate phase.
- Workload-internal wall is the cross-engine authority. Carrick child CPU is a
  secondary mechanism signal; Docker CPU inside LinuxKit is not substituted.
- Report medians, ranges, and a bootstrap interval or the repository's paired
  statistics where pairing is valid.
- A result must census the intended tier and produce the exact expected output.

Acceptance is no more than 2.0x Docker for both canonical workload families;
1.0x is the stretch outcome. Ratios are always named by workload shape.

## 5. Residual-overhead campaign

Once Tier D correctness is stable, translation/emit/cache/publish work is no
longer the target. Establish a fresh Tier-D residual budget for each canonical
workload:

1. clean end-to-end wall and Carrick child CPU;
2. untraced host-user / Darwin-kernel CPU split with the tracer excluded;
3. authenticated Tier-D syscall and phase census;
4. AMP1 amplification ledger for the workload's top guest operations, with
   drop/lifecycle closure;
5. source- and KDK-address-bound attribution for any non-syscall kernel family.

Select one source-distinct mechanism only when it has at least 10% plausible
end-to-end opportunity on Node or CPython. Test one hypothesis at a time:

- prove the mechanism with DTrace or LLDB/event-ring evidence;
- add a red control or deterministic fixture;
- implement the smallest semantics-preserving change;
- remeasure the mechanism;
- retain it only if a clean same-workload comparison wins without correctness
  regression.

Mechanism wins below the official noise screen may be retained when they are
repeatable, general, and reduce amplification, but they are not booked as a
scoreboard improvement without the clean comparison. Negative results remain
durable evidence and close that line.

## 6. Failure behavior and observability

- Zero census events or zero trace events is an error, not evidence that a
  path did not occur.
- Every Tier-D refusal/leave includes image, file offset or guest VA, raw word
  or syscall outcome, and process/thread identity.
- Fatal native records and the always-on event ring remain authoritative for
  faults that complete before a debugger can attach.
- A DTrace capture must follow progeny and declare perturbation; wall from a
  perturbed capture is never the performance authority.
- Unproven executable bytes, W^X transitions, fork states, or signal states
  fail closed. The campaign does not trade correctness for a lower ratio.

## 7. Test strategy

The test pyramid for each blocker is:

1. focused unit test for the encoding, state machine, or Darwin primitive;
2. mutation/red-control proving the test fails when the safety condition is
   removed;
3. smallest native Tier-D ELF or OCI reducer;
4. originating Node/CPython case against Docker;
5. focused native smoke set;
6. complete native smoke plus serialized `just ci` before the default flip.

For the first encoding family, the tests must include:

- `0x38764d52` is independently classified as unallocated and does not refuse
  an otherwise eligible image;
- `0x38764952` remains a valid x18-using `ldrb` and is veneered rather than
  skipped;
- changing any fixed family bit outside the proven mask does not accidentally
  broaden acceptance;
- the real Node and stripped-libcrypto byte windows pass the scanner without a
  word-specific exception.

## 8. Durable artifacts and commit discipline

- Design: this file.
- Implementation plan:
  `docs/superpowers/plans/2026-08-07-tier-d-node-python-default.md`.
- Baselines and comparisons:
  `docs/perf-results/2026-08-XX-tier-d-node-python-*.md` plus machine-readable
  JSON under the same evidence convention.
- Raw traces, binaries, and receipts remain under `target/perf/tier-d/` and are
  referenced by hashes.
- The root `handoff.md` is updated after every accepted blocker or performance
  candidate so controller state never trails code.

Commits stay narrow: safety decoder, each lifecycle blocker, measurement
harness, default flip, and each retained performance mechanism are separate.
The unrelated untracked `proposed-plan.md` is user-owned and remains untouched.

## 9. Rejected alternatives

- **Word whitelist for `0x38764d52`:** not a safety proof and would recur on
  the next data word.
- **Treat all decoder failures as invalid instructions:** false; `bad64` does
  not decode every valid AArch64 SIMD/extension instruction.
- **Assume executable-section bytes are code or data by disassembly shape:**
  stripped ELFs erase the mapping-symbol authority, and reachability guesses
  can silently miss indirect entries.
- **Silent mid-run fallback to Tier T:** incompatible memory/execution models.
- **Correctness-only default flip:** leaves the measured 8.0x CPython residual
  untouched and does not meet the product objective.
- **Universal Tier-D/T hybrid rewrite before observing V8:** too wide and
  speculative; the current blocker ladder can expose the exact executable
  transition first.

## 10. Completion audit

The goal is complete only when current evidence proves all of the following:

1. Tier D is default-on for eligible PIE images with exact `=0` rollback.
2. Canonical Node and CPython correctness cases match native-arm64 Docker and
   census direct execution without leaves or unnamed crashes.
3. Complete native smoke and serialized `just ci` pass at the shipped tip.
4. Canonical Node and CPython workload ratios are each no more than 2.0x
   Docker under the protocol above, or better; 1.0x remains the stretch target.
5. Every retained performance change has repeatable mechanism and end-to-end
   evidence bound to source, binary, workload, OS, and receipts.
6. `handoff.md`, design, plans, and evidence docs describe the same current
   state, with projections clearly separated from measurements.
