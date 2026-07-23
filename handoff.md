# FreeBSD Native x86 Bring-up Handoff

**Date:** 2026-07-23
**Branch:** `perf/native-xstate-transfer`
**Scope:** FreeBSD/amd64 native DSR only. VMM/HVF/KVM/bhyve behavior is not an acceptance criterion.

## Current state

The FreeBSD native x86 lane is functionally broad and has retained the historical
428/428 corpus result during this effort, but the current tree does **not** yet
have a fresh complete 428-case oracle receipt. The latest local
`conformance_probes` invocation passed its test harness, but only compared 214
available amd64-musl oracle entries and reported four report-only differences;
164 probes had no cached oracle or Docker coverage.

Two wrap-up commits contain the session work:

- `d2c54e5c feat(runtime): harden native x86 execution state`
- `4661f73c diagnostics(native-x86): add repeatable workload gates`

`neutral-domains` remains opt-in. Do not make it the production default until
Tasks 43, 55, and 58 close.

## Completed progress

### Native execution and mapping correctness

- Coordinated executable epochs, edge/return-cache stop guards, exact thread
  registration and retirement, and fail-stopped mapping/protection transitions.
- Transactional ELF/interpreter/stack/vvar/vDSO publication and rollback.
- Permanent ephemeral treatment for executable `MAP_SHARED` aliases, including
  shared `mremap`, SysV, aperture, and partial replacement behavior.
- Lock-safe native fork/vfork and terminal multithreaded exec takeover.
- Retryable, exactly classified fetch, translated, cflow, xstate, and sensitive
  faults through the unified synchronous-signal path.
- Validated direct-copy fast paths for fully materialized, non-truncatable
  anonymous/private backing. Mutable shared/vnode backing retains
  kernel-contained SIGBUS-safe copies.
- Exact private-file physical privatization and inbound-write generation
  invalidation.

### Extended state

- Checked sensitive emulation for XSAVE, XSAVEOPT, XSAVEC, XRSTOR, and 64-bit
  forms with standard/compacted geometry and atomic restore semantics.
- Virtual x87/SSE/YMM/opmask/ZMM, PKRU, FCS/FDS, CET-disabled reads, complete
  MXCSR validation, and consistent CPUID/XGETBV filtering.
- Signal, nested signal, fork, and malformed-frame xstate preservation.
- Sensitive FXSAVE/FXSAVE64/FXRSTOR/FXRSTOR64 and 14/28-byte
  FNSTENV/FSTENV/FLDENV plus 94/108-byte FNSAVE/FSAVE/FRSTOR.
- Hostile-review fixes landed for FLDENV TOP rotation, 14-byte FOP retention,
  WAIT versus no-WAIT behavior, ordered side effects, and full FSAVE payload
  preservation.

### Workloads and tooling

- Final neutral-domains GnuTLS/Kaniko gate: exit 0, `real 428.13s`,
  `user 384.96s`, `sys 199.71s`.
- Packaged 25-case LTP gate: 23 PASS, 2 expected TCONF, 194 TPASS, no failures,
  breaks, or timeouts; `real 50.41s`.
- Comparable 20-output cc1 workload: exit 0, `real 330.32s`, 3,181,360 output
  bytes.
- Safe cc1 profile: 7,729 samples over 8 seconds in
  `/tmp/native-cc1-child-profile2.json`.
- Reproducible jobs-aware source-image, archive, DTrace, and offline profiling
  tools are checked in and documented.

## Final wrap-up verification

Run after the final code edits and before the commits above:

- `cargo test -p carrick-dsr-x86 --lib`: **116/116 passed**.
- FreeBSD native runtime integration, conservative policy: **43/43 passed**.
- FreeBSD native runtime integration, neutral-domains policy: **43/43 passed**.
- Focused `legacy_x87_state_helper`: passed under both policies.
- `cargo fmt --all` and `git diff --check`: passed.

Earlier current-tree gates also passed platform-FreeBSD `cargo check`, targeted
Clippy with `-D warnings`, native DSR execution/static-ELF tests, runtime native
units, and the packaged workload gates recorded above. A full post-commit `just
ci` was not run on this FreeBSD-only rig.

## Open blocker: generated x87 FIP/FDP

Task 58 is **not complete**. The checked legacy transfer forms are green, but a
hostile review found that ordinary copied x87 data instructions can expose JIT
or stale instruction/data pointers through a later FXSAVE/FNSTENV.

The tree contains an in-progress completed-instruction sideband:

- `X86DsrContext::{last_copied_x87_guest_va,
  last_copied_x87_guest_data_va,last_copied_x87_data_valid}`;
- emitter FIP/FDP witnesses for copied x87 instructions;
- runtime normalization in `native_freebsd.rs`.

A temporary live assertion around RIP-relative `fldt` first proved FIP stale,
then proved FDP zero. The final live pointer assertion was deliberately removed
from `legacy-x87-state.S` during wrap-up rather than commit an unstable test.
The broad suites are green, but the sideband is **not accepted** until the exact
live proof is restored.

Next engineer must:

1. Re-add a red-first live fixture that executes ordinary copied x87 memory
   forms and verifies guest-coordinate FIP/FDP and virtual selectors through
   both FXSAVE and FNSTENV.
2. Cover RIP-relative, base/index, addr32, guest-r15, address zero, and FS-based
   addressing. Confirm scratch allocation cannot exceed the two context spill
   slots; fail closed during planning if an exact form cannot be emitted.
3. Verify asynchronous exits cannot consume a partial FDP publication and that
   register-only/control x87 forms preserve the prior FDP/FIP correctly.
4. Run both policy suites and obtain a fresh hostile native-only review before
   closing Task 58.

Relevant files:

- `crates/carrick-dsr-x86/src/{decode.rs,emit.rs,gateway.rs,gateway_x86_64.S}`
- `crates/carrick-dsr-x86/src/{fxstate.rs,legacy_x87.rs}`
- `crates/carrick-runtime/src/native_freebsd.rs`
- `crates/carrick-dsr-x86/tests/fixtures/legacy-x87-state.S`
- `crates/carrick-runtime/tests/native_freebsd_x86.rs`

## Remaining acceptance work

1. **Task 58:** close generated copied-x87 FIP/FDP and pass hostile review.
2. **Task 55:** rebuild the finalized release and rerun the pinned jobs=8 full
   source-image build. Preserve wall/user/sys timing and exact archive digest.
3. Run a true fresh full conformance comparison. Do not describe the partial
   214-case report-only run as 428/428 evidence.
4. Run the exact archive on a native Linux/amd64 host when one is available.
5. Update `docs/native-x86-ltp-readiness.md`, decide the default xstate policy,
   then close Tasks 55 and 43.

## Task state

| Task | State | Notes |
|---|---|---|
| 43 — synchronized executable invalidation | In progress, blocked by 55 | Core epoch/quiesce implementation and native tests are present; final workload/oracle acceptance remains. |
| 55 — epoch performance revalidation | In progress | GnuTLS, packaged LTP, and cc1 receipts pass; finalized-release jobs=8 rerun and full oracle remain. |
| 57 — checked XRSTOR/xstate | Complete | 116 DSR units and both 43-case policy suites pass. |
| 58 — legacy x87 memory forms | In progress | Transfer forms pass; copied-instruction generated FIP/FDP proof remains. |
| 8 — full LTP source image | In progress | Prior jobs=8 artifact passed native smoke; rerun after final release and Linux same-artifact oracle remain. |
| 9 — documentation and commits | Complete with this handoff commit | Code and diagnostics commits listed above. |

## Preserved artifacts

- GnuTLS/Kaniko: `/tmp/native-copy-gnutls-final.{out,err,status}`
- Packaged LTP JSONL: `/tmp/native-ltp-packaged-j8-neutral.jsonl`
- LTP archive: `/tmp/carrick-ltp-native-built-j8-neutral-20260529.tar`
- Archive SHA-256:
  `a1b15d8ebf7cd9f46df312183202a2df7c89ba5a59c04a705ef41367abf42b7a`
- cc1 profile: `/tmp/native-cc1-child-profile2.json`

Treat `/tmp` artifacts as local receipts, not durable source control. Recreate
or copy them before relying on them from another host.

## Operating constraints

- Never read Linux/GPL kernel source; use specifications, man pages, and the
  differential oracle.
- Do not use fasttrap/USDT/pid-provider DTrace on a continuing native process.
  Use the checked-in safe kernel-provider/offline profiling workflow.
- Fork waits must remain bounded and roll back without calling `fork`.
- Guest xstate must never be physically restored into host state or copied via
  unchecked guest pointers.
- Carrick and Docker oracle phases must not run concurrently.
- Keep acceptance claims explicitly FreeBSD native x86 only.
