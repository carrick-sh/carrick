# HVPatch Task 6 resumable checkpoint — 2026-08-15

This is an **integration and resume checkpoint**, not a Task 6 completion
claim. HVPatch remains opt-in, `baseline.hvpatch.jsonl` is not blessed, and the
default backend remains `native`.

Policy update after this checkpoint: HVPatch is the sole forward lane.
Regressions in the retired `native`/DSR and `vmm` lanes are explicitly accepted
and do not block integration; their results are historical context only.

## Exact source checkpoint

- branch: `codex/hybrid-kernel`
- implementation HEAD:
  `88aa86494d5edf6c6b60bd739c0bc4fcf95e909c`
  (`fix(hvpatch): reconcile task wakes before guest entry`)
- base `main`: `53f5da3f589b805c1eeff0a76545fb308719fde1`
- ancestry at capture: `main...HEAD = 0 125`
- signed binary SHA-256:
  `9eb908e9c8e2695024d294b651dde442c5c2d43687a955fbb2462b3fe240b077`
- signed binary CDHash:
  `6aa0f3ad0f773c7b5fa172c707ea3ff32015581f`
- Mach-O UUID:
  `BD707A48-8CCA-32D2-85F4-7F6D63B3F501`
- `com.apple.security.hypervisor` entitlement: present
- `__DATA,__dof_carrick`: present

The source worktree was clean when the implementation checkpoint was frozen,
before this controller/evidence update. No Carrick process survived the final
scoped census.

## Proven milestones retained in this branch

Tasks 1–5 are complete at the commits and evidence documents named in
`hybrid.md`. Their last exact evidence heads passed `RUST_TEST_THREADS=1 just
ci` and independent review.

The fresh line-exact HVPatch probe gate is green on the implementation above:
400 PASS occurrences, 400 unique names, and 0 FAIL / CRASH / KNOWN-GAP. The
serialized Carrick-then-Docker run completed in 331.21 seconds. Its raw log is
`target/conformance/task6/hvpatch-probes-wakegen-final-r3.log`, SHA-256
`9e88d62f74af314533efc0ae87750a05e9f1463f95c8a59b2aaf0ebfa7df3437`.

The deterministic 396/400 checkpoint failures were closed without changing a
probe or baseline:

- `ea61dcf6`: long timed waits selected for vCPU reclaim can no longer be
  silently changed back to park by the generic policy (`threadspawn`,
  `procladder_mt`).
- `29d9c602`: clone TID publication reuses the shared sparse page-table editor
  instead of reading TTBR0 from a reclaimed parent vCPU (`execthreads`).
- `c0e5d412`: absent pages inside the semantic mmap arena remain on the
  identity route rather than being misclassified as low alias holes
  (`mremapgrow`).
- `b38ad222`: process-directed publish, signal-frame inject/restore, and raw
  vCPU-kick results now have one typed diagnostic path, retained in
  `scripts/dtrace/hvpatch-sigchld-delivery.d`.
- `88aa8649`: each task wake has a durable generation that HVPatch reconciles
  at the safe guest-entry boundary. A successful-but-host-side HVF kick can no
  longer defer SIGCHLD until a later syscall. Native and mature VMM bypass this
  branch; the HVPatch steady path adds one Acquire load and comparison.

The exact final signed binary passed 30/30 untraced SIGCHLD stress runs and
10/10 Carrick-vs-Docker SIGCHLD comparisons. The four original checkpoint
failures passed 12/12 focused comparisons. Raw receipt SHA-256 values are,
respectively, `0d43301e69505a4c23faf911d04f46bac05a6c4328dbf2dc7ea5a996e384c764`,
`dbb544fcbc40ab0185022cd1cfd99c3e32b4911c368903bfb9fd10bb382055fb`,
and `8749abf8c5fb10d91df3deb2db576438fd9e9f9cb8b9752405a0185140613ded`.

The final sparse private-mmap implementation removes the per-mm 32 GiB
physical/stage-2 reservation. It leaves the hidden mmap arena semantically
reserved and materializes exact private VMAs with global-frame leases on
commit. It does not use the rejected VM-wide shared-zero frame design.

Fresh focused evidence at `def32e41`:

- page-table tests: 34/34
- committed-low-VMA runtime regression: 1/1
- HVPatch library tests: 171/171
- touched-crate Clippy with `-D warnings`: exit 0
- signed `/bin/true`: exit 0
- fork-child `go tool -n compile`: 3/3
- `go/types` `TestIssue13898`: 5/5
- `go/types` `TestIssue59944`: final clean sample 5/5
- full signed `go/types`: 574 RUN / 571 PASS / 3 expected SKIP / 0 FAIL,
  21.0 seconds

## Exact Go ecosystem checkpoint (pre-probe closure)

At `def32e414826b219a56e549ce8141f562fff1caf`, the signed HVPatch Carrick
phase accounted for all 194 declared Go rows, serialized with one worker and
cached current Docker oracles:

- 181 MATCH
- 3 existing non-gating DIFF:
  `go-crypto_sha512`, `go-crypto_subtle`, `go-syscall`
- 2 REGRESSION
- 8 CARRICK_CRASH

Raw JSONL SHA-256:
`73dc6ef99dd5cb8c91af62d49bf42b6df4ef7cdbffcc30c69fdd95c3be929e99`.

A clean serialized rerun of the ten gating names cleared `encoding/gob` and
`go/internal/srcimporter`. Eight real residuals remain:

| row | exact clean result | first attributed boundary |
| --- | --- | --- |
| `go-go_internal_gcimporter` | crash after 2/2 pass, 2 skips | fork quiesce timed out with registered non-guest tids 731/732, then sibling start-gate timeouts |
| `go-net` | crash after 280/280 pass, 76 skips | `TestSplice/tcp-to-unix/big` reports broken pipe and helper exit 2, then teardown hangs |
| `go-net_http` | crash after 1315/1315 pass, 72 skips | terminal teardown retains three processes after the complete pass stream |
| `go-os` | 713/729 pass, 16 fail, 18 skips | four top-level differential groups remain, including executable and pidfd behavior |
| `go-os_exec` | crash after 30/30 pass, 1 skip | fork reservation returns EAGAIN while TaskId(1) has a preparing operation; later pthread creation aborts |
| `go-os_signal` | crash after 10/10 pass, 1 skip | stops during `TestNohup` |
| `go-runtime_pprof` | 91/93 pass | `TestMapping` / `tracebackGo+C`; mapping helper exits by SIGABRT/status 2 |
| `go-testing` | crash after 69/69 pass, 2 skips | stops during `TestFlag` |

Clean residual JSONL SHA-256:
`ae5b05ab2d80df1f876f1317f4e6ee2380bff2d627fae045750fe6e3cf425147`.

Key ignored raw receipts were hashed before scoped cleanup:

- gcimporter stderr:
  `969526fb645df5dbcd5910686eb23d8894b72ad38c6221ab0face2f4b35fa079`
- net stdout/stderr:
  `3f2e6c5c299acaccf986783c8d5b55c44181f5d0755ff4c9487a07b92f2a49df` /
  `52ad8cda1a00615171c83ef510647dee858aa5d719b588823bb5dec8f7d71165`
- net/http stdout:
  `e679852bc8acb33e65ecad685fe9a7c7d5735359bce16138aa682d25f88c275b`
- os/exec stderr:
  `e6de95530cfd98d05829ba8a5bbb15b9f7f6b0a0536d6f77edc9170a26962baa`

The net and net/http hangs were terminated only through their exact
`CARRICK_RUN_ID`; each cleanup reported the scoped process count and zero
remaining processes. No unscoped kill was used.

## Architecture work still required

The controller goal requires one Darwin host process and one HVF VM. Current
raw/private HVPatch topology still has an NsSupervisor, one VM/guest carrier,
and a detached FileAuthority helper. Logical Linux fork/clone already stays
inside the carrier; a future HVPatch-only migration must bypass the supervisor
and use an in-process FileAuthority while leaving mature VMM/native behavior
unchanged.

CPython's exact 3.12.13 source/image and all 438 declared module names are
restored, but the 438-row Carrick/Docker phase has not run on this checkpoint.
The three Node rows also remain. Therefore neither baseline blessing nor the
HVPatch default switch is permitted.

## Terminal-scope addendum at `8513d8677`

The `TestCorrectMethodPackage` stop-the-world hang is closed without changing
suite semantics. Typed signed trace
`target/conformance/task6/task6-gcimporter-terminal-r2.dtrace` (SHA-256
`1881f4b775ebb9d4c7ea8a0895161c4be0b16732732c034ad217bea559e42bb5`)
proved that inner Go pid 20 Linux tids 22, 27, and 28 were retired from the
suspended vfork-parent path and then became the exact three `tgkill(SIGURG)`
`ESRCH` targets. None issued guest `exit(93)`.

The vfork wait had treated every clone-admission close as terminal. An
unrelated concurrent process fork temporarily publishes
`CloneAdmissionClose::Fork`, so three suspended vfork parents were retired as
if exec/exit had replaced them. `433e50347` adds a terminal-only predicate
(`Exec|Exit`) at this edge. Ordinary fork serialization and true exec/exit
cancellation remain intact. The regression test was red before the predicate
existed and is green with the fix.

Seven of eight signed untraced reducer attempts pass, including the final two
exact-source runs at 10.98 s and 11.51 s; every run had scoped cleanup zero.
The sole other attempt is the distinct, already-open sibling-materialization
start-gate timeout. It did not reproduce the retired-vfork root and remains
deferred with the other Go lifecycle residuals. A post-fix causal trace
recorded zero reason-3 terminals and zero `tgkill` `ESRCH`, but timed out after
emitting 1,091 other terminal receipts; its durable script is therefore marked
high-perturbation and is not a liveness gate.

The exact signed implementation-source binary at `8513d8677` is SHA-256
`a823acdf3c0ca8a00947a09f7680d3955f2a3edc1e49dcc6b38ce7fd053523f5`,
CDHash `f26469713b36d6e6d15296ef7531d2b15b476c39`, UUID
`759448DE-6473-3964-8B4F-29E87F188277`, with the HVF entitlement and
`__TEXT,__dof_carrick`. Formatting, typed-domain lint, affected-crate Clippy,
and focused signal/filesystem/admission/terminal-provider tests are green.

Per the explicit terminal scope, the following remain future work rather than
requirements for this checkpoint integration: the start-gate residual and all
remaining eight Go rows, HVPatch-only one-host-process migration, CPython and
Node phases, baseline/default changes, broad final CI/Tasks 1–5 proof, and the
cold-build regression signal. Native/DSR and legacy VMM are non-gating product
lanes. No baseline or default was changed here.

## Resume here

The next future-session correctness target is the remaining
fork-quiesce/start-gate cluster from the eight-row Go residual table above. The
STW/vfork-parent root is already closed and must not be reopened by inference.
Reproduce the distinct start-gate signature with the purpose-built child-first
debugger:

```sh
target/release/carrick debug lldb-run \
  --deadline-seconds 8 \
  --out-dir target/conformance/logs/lldb-runs/task6-gcimporter-quiesce \
  --run-id task6-gcimporter-quiesce -- \
  --max-traps 18446744073709551615 \
  --raw --fs host \
  -w /usr/local/go/src/go/internal/gcimporter \
  --exec-backend hvpatch \
  localhost:5005/carrick-go-conformance:1.24 \
  /conformance/go_internal_gcimporter.test \
  -test.v -test.run Test -test.short
```

After closing all eight Go residuals, rerun all 194 Go rows, then the 438
CPython and three Node rows in separate Carrick and Docker phases. Only after
those pass may Task 6 bless `baseline.hvpatch.jsonl`, select HVPatch as the
default, and run the final signed/CI/cold-build/review gates.

## Checkpoint integration gates

Before a partial, opt-in checkpoint is fast-forwarded to `main`:

1. commit this evidence document and the `hybrid.md` progress table;
2. run exact evidence-HEAD `RUST_TEST_THREADS=1 just ci`;
3. retain the source-identical implementation-HEAD 400/400 signed receipt
   above; rebuild only if the evidence commit changes executable inputs;
4. preserve the main checkout's dirty `hybrid.md` patch and verify the branch
   controller is its exact semantic superset;
5. fast-forward only after explicit user approval, then rerun CI on merged
   `main`.
