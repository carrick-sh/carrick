# Compact native lowering: compute gain, no material syscall gain — 2026-09-22

Compact lowering reduces the arithmetic control's elapsed time **31.6%** and the
load/increment/store control **9.1%**. It does **not** materially improve the
inotify syscall controls: invalid pairs are 2.9% slower and unchanged-watch pairs
1.9% slower by the invocation medians. These small syscall differences are not
statistically qualified regressions or equivalence results. Sustained churn is
1.5% faster. The candidate remains **opt-in**; the existing slot emitter remains
the default. There is no new product or full inotify09 speedup claim.

This experiment answers a causal question: instruction amplification contributes
substantially to compute cost, but removing it does not remove the main inotify
syscall cost. The 1x objective remains open. Further instruction compaction alone
is not the next priority for inotify09.

## Same-binary intervention

Both arms use the same preserved release test executable, unchanged Linux ELF,
carrier data and syscall-buffer paths, data-demand analysis and input-window
reuse. Only `CARRICK_NATIVE_CODE_LAYOUT=slots/compact` differs. Every SVC returns
through the same gateway and scope/dispatch boundary. All register/SIMD/flag
preservation, full-width memory bounds checks, virtual SP/TLS and maximum
256-backedge checkpoint interval remain.

There are three invocations per arm/cell, alternating arm order by case and
repetition. Each invocation has one warmup and nine retained samples. The table
uses the median of the three invocation medians, in ns per completed iteration.
All 36 paired invocations, 40 small semantic controls (five phases at 1/8/32/128,
both arms), and 18 fresh native ARM64 Linux invocations passed. There were no
builds, tracing or overlapping Carrick/Docker measurements during either phase.
The host CPU was not pinned. Every sample, including the variable first invalid
and unchanged-watch runs, remains in the receipts; there were no timing retries.

| Control | N | Slots ns | Compact ns | Time change | Linux ns | Compact / Linux |
|---|---:|---:|---:|---:|---:|---:|
| Invalid add/remove pair | 65536 | 589.013 | 606.269 | +2.9% | 251.903 | 2.41x |
| Two unchanged-watch adds | 65536 | 1205.060 | 1228.472 | +1.9% | 523.549 | 2.35x |
| Fresh churn | 128 | 1186.203 | 1185.219 | -0.1% | 1042.969 | 1.14x |
| Churn into queue overflow | 65536 | 1056.716 | 1041.393 | -1.5% | 906.757 | 1.15x |
| Arithmetic loop | 65536 | 2.958 | 2.023 | -31.6% | 0.656 | 3.08x |
| Load/increment/store loop | 65536 | 3.141 | 2.855 | -9.1% | 1.350 | 2.12x |

Arithmetic goes from 4.51x to 3.08x Linux, and memory from 2.33x to 2.12x. Invalid
and unchanged-watch pairs remain around 2.3–2.4x Linux. Fresh short churn has
substantial fixed clock-copyout cost and Linux variation; it is not a parity
claim. These fresh ratios supersede the previous screen for this experiment,
without rewriting any older receipt.

The timed watch loops contain no write/seek work. Path setup, event drain and
stdout are outside their timed interval. The first clock copyout remains inside
the interval. Native macOS I/O is not subtracted; raw Linux ratios remain visible.
The direct host-file design is unchanged. The pinned Linux image is
`localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`.
All paired requests/completions/errno counts, checkpoints and data activations
agree, and each Linux case has exactly the same ELF SHA-256.

## Change and contract

The slot emitter gives every guest instruction 64 bytes. Even simple arithmetic
loads x17, executes the guest instruction, stores x17 and branches to the next
slot. Compact bodies keep x17 live and emit ordinary arithmetic once with direct
fallthrough. Internal branches target bodies. Separate two-instruction entry
veneers restore x17 whenever the host enters at any legal guest PC. Memory and
checkpoint stubs spill/restore scratch state at their actual boundaries. The
existing assembly gateway and instruction whitelist are unchanged.

`kernel.execution.native-code-density` counts actual emitted instruction words,
including cold checkpoint stubs and entry veneers. For N adds plus SVC, the bound
is `3*N + 18`: N arithmetic words, 2*(N+1) entry words, and two eight-word
checkpoint stubs. The preserved pre-change binary passes semantic assertions
but fails at every scale: **48/160/544/2080 words** at 1/8/32/128. The final
compact path reports **21/42/114/402**. The largest fixture emits 80.7% fewer
words. This static density budget is not a dynamic instruction-count measurement;
elapsed-time evidence is separate.

The original red/initial green fixture lived in the research crate. Registry
validation requires a workspace crate binding, so the same arithmetic/control
fixture moved to `carrick-runtime::vcpu_loop::memory::tests::native_floor`.
Its text bytes, scales, expected registers, observation identity and budget are
unchanged; its unused data segment uses the runtime ELF helper. Final observations
are bound to the final source and preserved runtime executable. No budget was
weakened to repair the binding.

Tests include all 14 conditional branch conditions under all 16 NZCV values,
32/64-bit CBZ/CBNZ joins, unconditional edges, exact guest-PC re-entry, callback
updates to x17, backward-edge counts around 255/256/257 and 1024, virtual reserved
registers/TLS, and all GPR/SIMD/FP control state. The existing **12,288-case**
scalar load/store differential now explicitly selects compact emission, including
scratch aliases, SP, zero registers, widths and offsets. Permission, out-of-range,
wrong-publication and revoked-publication controls also remain.

The design follows the direct-link and register-restoration principles described
in DynamoRIO's [AArch64 linking guide](https://dynamorio.org/page_aarch64_far.html)
and [register-management guide](https://dynamorio.org/page_drreg.html). Its primary
BSD license and pinned source receipts remain in
[permissive-guidance](../permissive-guidance/sources.json). These are architectural
guidance, not Carrick timing evidence. No third-party implementation was copied.

## Carrier publication audit and next work

The initial investigation confirmed that wiring the existing instruction reader
into `Code::publish` would not establish executable authority:

- `InstructionRead::validate_mapping` authenticates the execution lease and
  backend/VMA/inventory revisions. Its own contract explicitly excludes in-place
  executable-byte changes and execution permission for a code cache.
- `CarrierForeignPreparedWrite::commit` copies bytes and performs host instruction
  cache maintenance. It does not revoke a translated block or advance a shared
  executable-content generation. The publication classifier uses the target
  mapping's executable ranges; a writable non-executable alias needs backing-wide
  coverage too.
- Ordinary and privileged core writes pass through
  `Aarch64EngineCore::{write_bytes_raw,write_bytes_unchecked}` and translated
  backend writes. Guest stores, shared aliases, loader/patcher updates and
  protection transitions also need a coherent writer/publication protocol.

No carrier code-publication API or native product entry was added in this pass.
The compact emitter remains on the prior private research text authority. This
is an explicitly bounded detour with a measured result, not completion of the
carrier integration promised as the next delivery step.

The next deliverable is a carrier-owned executable-content generation and
revocation transaction, keyed by physical backing ownership/range and tied to
mapping/execution identity. Revoke before a writer can alter bytes; drain only
affected active executions; publish new translations only from authenticated
instruction reads. The capability must account for writes through other VAs/MMs,
unmap/remap, mprotect, fork/COW and exec. For a first private RX implementation,
any unsupported writer or writable/shared alias must make native execution
ineligible and preserve the existing execution path. Do not infer immutable text
from RX permission or a retained owner pin alone. Do not copy/hash all text at
every syscall or hold mutation exclusion across guest work to conceal the gap.

The decisive tests are two live MMs at the same VA, execute-only fetch, direct and
alias writes, revocation between read/compile/entry, active-executor drain,
address/owner reuse, and unmap/permission restoration without resurrecting old
code. Bind these to signed execution before extending opcode coverage or claiming
full inotify09/Node/Go/Python delivery. The existing signed sparse-publication
budget failure remains a separate open gate.

For syscall time, the next cost experiment should consolidate the redundant
entry/dispatch authority checks through a typed checkpoint capability. It must
end native pointer/running scopes before dispatch, retain exact task/MM/lease
identity, and refresh mutable resources normally. Extending captured file-table
leases across guest execution or calling dispatch inside a running scope is not
an acceptable shortcut. This is a hypothesis, not an implemented or measured
speedup. Use the previous >=10% invalid/unchanged-pair improvement screen to
prioritize it; do not extrapolate the compute gain to syscall-heavy workloads.

## Verification and receipts

- Final emitter suite: 16 passing tests. The density fixture moved to runtime.
- Carrier memory suite: 42 passing tests, 3 deliberately ignored diagnostics.
- `just test-kernel`: 2,377 passing tests across 20 test-result records; one
  pre-existing ignored controller-receipt test. Serial-host tests remain outside
  this recipe, as defined by the repository.
- Observability: 83 passing tests. Contract package: 33 passing tests.
- Affected all-target Clippy, scoped formatting, whole-worktree diff check,
  inventory/registry and product dependency-layering checks pass.
- 76 research run IDs report zero remaining scoped processes; all 18 Docker
  containers are removed. The parent processes completed successfully.

Retained setup failures: a new TLS/XZR test encoded an instruction the existing
whitelist refuses (the test now asserts refusal); a receipt environment variable
was initially relative to Cargo's crate cwd (the harness uses absolute paths);
Clippy rejected host-file writing in the new Rust fixture (receipt writing moved
to the external driver); and the registry rejected the research-crate binding
(the actual fixture moved to runtime). All failed logs remain. No executable
permission check, semantic assertion, measurement sample or budget was relaxed.

`manifest.json` binds the measured and final source maps, preserved executables,
unchanged frozen product/research binaries, raw logs and observations. The
measured-to-final changes select the old default again, move receipt/fixture
plumbing and add documentation/registry metadata. The compact lowering module,
gateway and measurement driver are unchanged. The release measurements belong
to the preserved measured executable, not a rebuilt later artifact.

All work is local and uncommitted. No product CLI, guest default, signed native
execution, full inotify09 run, ecosystem differential, full CI, or product
probe/smoke/full promotion is claimed. The previous
`fresh_sparse_publication_avoids_stage1_maintenance` failure (one invalidation
against a zero budget at scale 1) was not rerun or declared resolved here.
