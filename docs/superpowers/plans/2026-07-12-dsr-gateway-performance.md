# Native DSR Gateway Performance Plan

> **Status (2026-07-12):** complete. The deferred-kick candidate passed the
> focused correctness, fixed-order ABBA, and full serial CI gates and is
> promoted.

**Goal:** reduce the signed native DSR syscall floor by at least 5% without
weakening Linux-visible register state, Darwin ABI conformance, asynchronous
kick delivery, signal/fault recovery, fork correctness, or static/dynamic PIE
workloads.

**Baseline:** `docs/perf-results/native-dsr-gateway-baseline.jsonl` records 30
untraced static-PIE processes. Median process p50 is 0.474 us scalar and 0.625
us SIMD, with 0.003 us IQR for each. The SIMD lane includes fixed guest-side
seed/verify instructions; the gateway itself currently saves/restores full
SIMD state for both lanes, so their difference is not a SIMD gateway-cost
estimate.

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/gateway_aarch64.S`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`
- Modify: `crates/carrick-cli/tests/dsr_trace_overhead.rs`
- Use: `conformance-probes/src/bin/perf_dsr_gateway.rs`
- Create: `docs/perf-results/native-dsr-gateway-components-v1.jsonl`
- Create: `docs/perf-results/native-dsr-gateway-candidate-v1.jsonl`

## Instruction audit

The checked-in release disassembly matches
`gateway_aarch64.S`; `_carrick_dsr_enter_raw` starts at `0x100525cb4` in the
frozen baseline binary and `_carrick_dsr_exit_common_start` at `0x100525e00`.
The exact address is provenance, not an ABI.

| Instruction group | Classification | Decision |
|---|---|---|
| Save/restore host SP and x19-x30 | Darwin host ABI | Keep. The gateway branches away and later returns to its Rust caller. |
| Save/restore host q8-q15 | Darwin host ABI | Keep at least d8-d15. Full-q preservation exceeds the ABI, but using d pairs keeps the same eight instructions and is not a 5% candidate. |
| Call guest/host ABI closures | Signal recovery and custom-x18 ABI | Keep until separately measured. They publish/clear the active context, toggle custom x18, and open/close the SIGPIPE kick window in the required order. |
| Restore/capture x0-x30, SP, and PC | Guest-observable Linux state | Keep. Physical x17/x28 staging and virtual x18/x28 are covered by recovery oracles. |
| Restore/capture NZCV | Guest-observable Linux state | Keep; a Linux syscall does not authorize flag corruption. |
| Restore/capture FPCR and FPSR | Guest-observable Linux state | Keep. |
| Restore/capture q0-q31 | Guest-observable Linux state | Keep. A scalar current block does not prove inherited SIMD state dead. |
| Gateway phase/status/target publication | Signal/fault/kick recovery | Keep. Phase 2 is the stable-snapshot boundary used by asynchronous recovery. |
| Restore host q8-q15 and x19-x30 after closure | Darwin host ABI | Keep. |

**Conclusion:** no unconditional assembly instruction is proven redundant.
Static scalar/SIMD specialization is architecturally invalid because state may
have been produced by an earlier directly linked block. A future lazy-SIMD
design would need per-thread residency/dirty state across the whole translated
chain, signal materialization, fork reset, and an oracle proving every state
transition; it is not authorized by this plan.

The release disassembly also shows a call to `memcpy` with length `0x340`
(832 bytes, exactly `NativeUcontextSnapshot`) immediately after
`_carrick_dsr_enter_raw` returns. `DsrContext::new` embeds another full snapshot
and initializes a 1200-byte frame before entry. These wrapper costs and the ABI
closure calls are plausible structural long poles; they must be separated
before code changes.

## Task 1: Attribute closure and wrapper costs

- [x] Add ignored, opt-in release microbenchmarks for (a) one paired
  `carrick_native_dsr_enter_guest_abi` / `enter_host_abi` closure on a correctly
  initialized thread and (b) `DsrContext` construction plus snapshot
  publication with all values passed through `black_box`.
- [x] Use the same 16-operation batches, 20,000 samples, 30 process
  repetitions, counter conversion, and positive finite checks as the gateway
  probe. Do not use DTrace on the hot boundary.
- [x] Record raw arrays, p50/p95/min/IQR, release binary hash, and power facts
  in `native-dsr-gateway-components-v1.jsonl`.
- [x] Select a component only if its stable p50 is at least 20% of the 0.474 us
  scalar baseline in two independent 30-run campaigns. Otherwise stop and
  profile a broader dispatch boundary.

**Selection result:** the ABI closure is selected. Its process-p50 median is
0.211 us in both campaigns, 44.5% of the 0.474 us scalar gateway baseline.
Wrapper construction/publication is 0.026 us in both campaigns, only 5.5%, so
Task 2A is deferred. Exact arrays and provenance are in
`docs/perf-results/native-dsr-gateway-components-v1.jsonl`.

## Task 2A: Reuse the gateway frame only if wrapper cost wins

- [ ] Write red ownership tests proving one frame per `ThreadTranslator`, no
  sharing between guest threads, clean fork-child reset, and no active-context
  pointer surviving an exit or error.
- [ ] Move the authoritative snapshot into a per-thread gateway frame so the
  832-byte ingress/egress copy is removed rather than moved. Expose typed
  snapshot access to dispatch. Do not put mutable frame state in the
  process-wide translator/cache.
- [ ] Preserve every compile-time offset assertion and the physical-x28
  contract. Signal capture must continue to see a contiguous snapshot at
  offset zero and phase/status metadata at their established offsets.
- [ ] Reject a variant that merely reuses allocation while retaining both
  snapshot copies; it has not addressed the measured component.

## Task 2B: Optimize the ABI closure only if closure cost wins

**Selected by Task 1:** yes; decompose before changing behavior.

- [x] Decompose custom-x18 transition and signal-mask transition with exact
  benchmark-only entrypoints around the production primitives. This proved
  lower-perturbation than adding even a disabled counter branch to the hot
  gateway; it emits once per process and adds no production-path work.
- [x] Preserve the ordering invariant: publish context, enter custom-x18 ABI,
  then make kick delivery available on first entry; enter host x18 ABI before
  clearing context on exit, so an arriving signal is handled on exactly one
  side of the active-context boundary.
- [x] Any signal-mask replacement must retain Darwin-native signal delivery
  with a linearizable capture/consume boundary. Polling-only or lossy delayed
  delivery is rejected.
- [x] Run the phase-zero, phase-one, phase-two, pending-kick, signal, fault,
  custom-x18, and fork-child oracles red-first against any reordered closure.

**Decomposition result:** the paired SIGPIPE unblock/block transition is
0.201 us p50 in both 30-process campaigns, 95.3% of the selected 0.211 us
closure. The custom-x18 pair is 0.005/0.008 us. Reusing a prebuilt `sigset_t`
only lowers the mask pair to 0.198 us, proving that set construction is not the
long pole. Evidence is in
`docs/perf-results/native-dsr-gateway-closure-decomposition-v1.jsonl`.

**Implemented candidate:** SIGPIPE is unblocked once per initialized thread and
remains deliverable while host or translated code runs. A signal with no active
DSR context consumes the requested kick into thread-local deferred state; the
next gateway entry publishes `KickAtEntry` before executing translated code.
Handler installation clears inherited deferred state in a fork child. Red-first
tests proved host-window delivery, entry consumption, and fork reset before the
implementation was retained.

## Task 3: Candidate promotion gate

- [x] Freeze distinct signed baseline/candidate binaries by SHA-256, inode,
  CDHash, and source commit. Use fixed ABBA order and 10,000 seeded bootstrap
  median-ratio resamples.
- [x] Run at least 30 static-PIE gateway repetitions per role. Require scalar
  p50 improvement at least 5% with 95% upper ratio below 1.0. SIMD sentinel
  preservation is exact; SIMD p50 may not regress more than 1%.
- [x] Run the existing batch-16 syscall floor and direct V8 gates. Each upper
  ratio must remain at or below 1.01.
- [x] Run Rust static PIE, Rust dynamic PIE through its real loader, Go PIE,
  vfork sibling exec, non-leader exec, full-state, signal/kick/fault, and fork
  reset proofs.
- [x] Run `RUST_TEST_THREADS=1 just ci`. Record any ordinary parallel-suite
  flakes separately; do not waive focused failures.
- [x] Promote only if all thresholds pass. Otherwise restore the candidate and
  keep its evidence as a rejected experiment.

**Promotion result:** the scalar gateway p50 fell from 0.471 to 0.273 us
(ratio 0.5796, 95% interval 0.5778-0.5860), and the batch-16 syscall floor fell
from 0.486 to 0.281 us (ratio 0.5776, upper interval 0.5798). The SIMD gateway
improved from 0.625 to 0.443 us with exact vector sentinels, and direct V8
improved from 7663.36 to 7517.46 ms (ratio 0.9804, upper interval 0.9834).
Focused DSR oracles, static/dynamic PIE, Go PIE, vfork/non-leader exec, and
clippy are green. Provenance and decisions are in
`docs/perf-results/native-dsr-gateway-candidate-v1.jsonl`.

## Stop conditions and next architecture

- If neither wrapper nor closure clears 20%, do not churn gateway assembly.
  Add a low-perturbation split around syscall decode/dispatch and native return
  publication, then select the next stable component above 30%.
- Do not infer dead SIMD state from the current block. Lazy SIMD is a separate
  architecture project requiring chain-wide state ownership and signal/fork
  materialization proofs.
- Do not use an in-process global cache or shared mutable gateway frame; real
  host forks and multiple guest threads make either design incorrect.
