# Native DSR-only backend and HVF comparison design

**Date:** 2026-07-12

**Status:** approved

**Scope:** Darwin-native AArch64 execution and matched native16k/HVF performance measurement

## Purpose

Remove Carrick's native `brk` execution vehicle completely and make the dynamic
syscall rewriter (DSR) the only Darwin-native instruction-execution path. Then
extend Carrick's existing performance framework to produce a report-only,
matched comparison of native16k and HVF using identical guest artifacts.

This design removes Carrick-generated AArch64 `brk` instructions, the legacy
SIGTRAP syscall transport, and the public native code-mode choice. It does not
remove Linux `brk(2)` heap semantics or guest-authored AArch64 `brk` behavior.
Those remain guest ABI requirements.

## Fixed decisions

- Darwin-native execution is DSR-only.
- Carrick must not generate or depend on AArch64 `brk` instructions for native
  syscalls, sensitive-instruction handling, control-flow exits, or test-only
  comparison paths.
- The `NativeCodeModeRequest` policy surface is removed rather than retained as
  a one-variant enum.
- DSR uses explicit branch gateways and typed exit state for every
  Carrick-owned transition.
- Linux `brk(2)` and guest-authored AArch64 `brk` retain Linux-visible behavior.
- Native16k and HVF performance results are report-only. Performance ratios do
  not gate correctness or fail CI.
- Invalid measurements still fail the deliberate measurement command. A
  timeout, missing metric, artifact mismatch, or invalid CPU normalization is
  not a performance verdict.
- The Linux/Docker oracle remains the semantic authority. No Linux kernel or
  other GPL implementation source is consulted.

## Native architecture

### Single execution path

Selecting the native backend resolves directly to the DSR thread loop. The
runtime no longer branches on an instruction-execution mode after resolving the
backend and page profile.

Remove `NativeCodeModeRequest` and every `native_code_mode` field from:

- `carrick-spec` requests and serialized run specifications;
- `carrick-engine` lowering;
- CLI `run`, `create`, `run-elf`, lifecycle, and persisted-container plumbing;
- runtime execution plans, memory objects, and image mapping;
- conformance lane construction and native test helpers;
- performance invocations and documentation.

Remove `--native-code-mode` and `CARRICK_NATIVE_CODE_MODE`. New invocations
that pass the old CLI option fail as an unknown argument. Newly persisted
container state contains no code-mode field. Existing persisted state that
contains `native_code_mode` remains readable through Serde's unknown-field
compatibility, but the value is ignored and is not retained, interpreted, or
copied into new state.

### Delete the legacy trap executor

Delete the in-place instruction patcher that converted `svc #0`, selected
system-register instructions, and `dc zva` into distinguished `brk`
instructions. Delete its associated:

- `BRK_NATIVE_*` constants and instruction constructor;
- SIGTRAP syscall run loop and trap counter;
- native trap enum and decoder;
- snapshot/resume paths used only by the legacy trap executor;
- detached-context transport branches used only by that executor;
- legacy trace output and tests;
- `native_exec_probe` `brk-trap` feasibility case;
- current documentation presenting the executor as supported or selectable.

Shared fork, exec, signal, ucontext, and thread-lifecycle helpers remain where
DSR uses them. Their names and comments must be updated when they still describe
the removed executor.

### Remove internal DSR `brk` sentinels

Delete all `BRK_DSR_*` constants and any helper that emits a `brk` word for a
planned exit. Production emitted blocks already have explicit gateway exits for
syscalls, direct and indirect control flow, sensitive instructions, continued
translation, and unsupported instructions; those gateway branches become the
only valid Carrick-owned exits.

Delete the legacy-`brk` gateway oracle and its performance comparison. Replace
any test that depends on a sentinel with a test of the typed gateway exit or the
emitted branch sequence. An emitted-code invariant rejects Carrick-generated
AArch64 `brk` opcodes in translated blocks.

### Preserve guest semantics

The deletion must not conflate three distinct concepts:

1. Linux `brk(2)` remains implemented by guest heap-end tracking.
2. A guest-authored AArch64 `brk` remains a guest instruction. DSR classifies
   it and produces Linux-visible SIGTRAP behavior through the normal signal
   path.
3. A host SIGTRAP is no longer a Carrick-native syscall or control-transfer
   event.

The native signal/ucontext layer remains responsible for DSR fault recovery,
kicks, and guest signal delivery. It must not install or classify a SIGTRAP as
a private Carrick transport. Signal masks and handler installation should be
narrowed accordingly without changing guest-visible SIGTRAP delivery.

## Performance framework

### Backend-pair mode

Extend the existing `perf_support` framework and deliberate benchmark command
with a native16k/HVF backend-pair mode. Do not create an independent benchmark
tool or post-process unrelated logs.

For every comparable case:

- resolve one guest artifact and compute its SHA-256 before sampling;
- invoke native with `--exec-backend native --native-page-profile native16k`;
- invoke HVF with `--exec-backend hvf`;
- pass no native code-mode option;
- use the same binary, guest arguments, environment, filesystem mode, CPU
  exposure, and metric key for both backends;
- reject the row if the resolved artifacts or declared workload inputs differ.

The runner remains serial. A drift-balanced sampling block is:

1. native16k;
2. HVF;
3. HVF;
4. native16k.

Each process completes before the next starts. Existing cooldowns, deadlines,
scoped `CARRICK_RUN_ID` cleanup, and the prohibition on concurrent heavy lanes
remain in force.

### Comparable workload surface

Run each registered performance case that can execute identically under both
backends. At minimum, the campaign covers:

- syscall trap/floor and scalar/SIMD gateway crossing;
- private futex handoff, blocking pipe wakeup, and epoll wakeup;
- representative syscall-burst cases;
- anonymous mapping churn;
- fork and fork/exec;
- declared zero-memory and 256 MiB fork-scaling points;
- direct V8 as a separate matched signed-workload comparison using the same
  statistics and provenance model.

A registered case that requires backend-specific transport is not silently
adapted. It produces a machine-readable skip with the case name and exact
reason. The report distinguishes unsupported comparison shapes from workload
failures and invalid measurements.

### Statistics and provenance

Reuse the existing summary, bootstrap, provenance, and JSONL facilities. Each
backend row records:

- raw samples;
- p50, p95, minimum, IQR, and sample count;
- workload, metric, units, and lower-is-better/higher-is-better direction;
- backend and lane;
- artifact SHA-256;
- git SHA and signed Carrick binary identity;
- exact invocation policy;
- host, operating-system, CPU, and CPU-exposure facts;
- run ID and timeout/cleanup policy.

Each comparison records the native16k/HVF median ratio and its seeded bootstrap
confidence interval. Report the ratio direction explicitly so throughput and
latency cannot be interpreted backwards.

The first campaign is report-only. A performance ratio never asserts, changes
the process exit status, or becomes a CI threshold. The deliberate command does
fail when it cannot produce a valid declared row: missing metrics, workload
failure, timeout, artifact mismatch, insufficient valid samples, or failed CPU
normalization are errors, not neutral results.

## Evidence report

Check in a dated evidence report and its machine-readable JSONL results. The
report contains four separate sections:

1. correctness and live-workload verification;
2. valid matched performance rows;
3. skipped or invalid rows with exact reasons;
4. workload-specific observations and limitations.

Do not declare a global backend winner. State only measured, workload-specific
ratios and confidence intervals. Keep measured results separate from
projections, historical measurements, and unsupported comparison shapes.

## Correctness and testing

### Red-first invariants

Before deleting implementation code, add focused tests that fail against the
current tree and prove the intended boundary:

- native execution plans expose no code-mode choice;
- the old CLI option is rejected rather than ignored;
- Carrick-generated DSR blocks contain no internal AArch64 `brk` exit;
- a guest-authored AArch64 `brk` still produces the Docker-matching Linux
  SIGTRAP result;
- backend-pair sampling rejects differing artifacts and emits its declared
  report-only schema.

Delete or rewrite legacy-only tests only after the new invariants are red.

### Focused verification

Run focused tests for:

- spec, engine, CLI arguments, lifecycle, and container serialization;
- native execution planning and image mapping;
- DSR block planning, emission, gateways, fault recovery, and signal delivery;
- DSR generation invalidation, JIT rewrite, and concurrent publication;
- native fork, vfork, exec, and non-leader exec;
- performance parsing, sampling order, skip/error classification, statistics,
  provenance, and JSONL schema.

### Live verification

After focused tests are green:

- run `just fmt-check`, clippy with warnings denied, `just lint-domains`, and
  `just ci`;
- build and codesign through `just build`;
- run the complete authoritative native16k musl probe lane and record the new
  measured aggregate;
- run signed Rust static PIE and dynamic glibc PIE;
- run signed Go static PIE and dynamic glibc PIE;
- run direct V8, JIT mutation, and concurrent first-publication workloads;
- run focused fork, vfork, exec, and non-leader exec workloads;
- run the matched native16k/HVF report-only campaign only after correctness is
  green.

Carrick and Docker phases remain serial. All guest processes use scoped run IDs
and are audited for leftovers after each deliberate campaign.

## Completion criteria

The work is complete only when all of the following are true:

- native Darwin enters DSR unconditionally;
- no public, persisted, or internal code-mode selector remains;
- no Carrick-owned native transport, control-transfer, sentinel, or comparison
  mechanism generates or depends on an AArch64 `brk` instruction; the focused
  guest-semantic fixture is the intentional exception because its subject is a
  guest-authored `brk`;
- the legacy SIGTRAP executor and `brk` comparator are deleted;
- Linux `brk(2)` and guest-authored `brk` semantics remain correct;
- focused tests, `just ci`, signed workloads, and the measured native16k probe
  lane pass;
- the backend-pair harness produces valid, provenance-complete native16k/HVF
  rows without enforcing performance thresholds;
- a checked-in evidence report states measured results, skips, invalid rows,
  and limitations without a global-winner claim;
- a repository audit finds no stale current documentation, CLI examples,
  environment variables, generated sentinels, or native trap-transport code.

Historical documents may retain past `brk` measurements when they are clearly
dated evidence and not instructions or current architecture claims. Historical
text is not rewritten merely to erase the record of how DSR was selected.
