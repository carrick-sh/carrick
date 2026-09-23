# Bounded native guest execution experiment — 2026-09-22

Follow-up: [native memory lowering](../native-memory/README.md) removes the
memory-loop regression described in this historical checkpoint. The original
measurements and limitations below are retained.

**Actual native guest execution now reaches approximately Linux cost on the valid
watch-churn reducer. General native execution remains unqualified.** The memory
control is pathological; this is not a full inotify09 or language-workload result.

Contract: `kernel.execution.native-synchronous-syscall`, still unresolved. Code:
[`experiments/native-syscall-slice`](../../../../experiments/native-syscall-slice/README.md).
No product execution backend was enabled, no passing binding registered, and no
contract budget weakened. The shipped CLI remains the frozen pre-experiment
artifact. Work is local and uncommitted.

## Final same-ELF results

Each cell is the median of three invocation medians, nine retained samples per
invocation. The first of ten guest samples is warmup. Native, HVF and native ARM64
Docker phases were serial, with no build or tracing during timing. The final
cohort has **54 successful invocations and 486 retained samples**. All raw records,
commands, executable hashes and scoped cleanup receipts are preserved here.

| Guest operation | Native slice ns/iteration | Frozen HVF | Linux | Native/Linux |
|---|---:|---:|---:|---:|
| Invalid add/remove pair, N=65536 | 469.18 | 2962.22 | 239.00 | 1.96x |
| Two unchanged-watch adds, N=65536 | 719.57 | 3517.32 | 505.23 | 1.42x |
| Fresh watch churn, N=128 | 772.13 | 3534.18 | 1015.63 | 0.76x |
| Churn growing into overflow, N=65536 | 749.12 | 3366.54 | 884.58 | 0.85x |
| Integer loop | 2.14 | 0.51 | 0.58 | 3.69x |
| Load/increment/store loop | 154.96 | 1.20 | 1.27 | **121.56x** |

The long valid churn loop takes **77.7% less time than HVF (4.49x faster)**.
That supports investing in native syscall transport. These are diagnostic
medians, without core pinning, randomized cross-arm order or confidence bounds;
they do not establish a universal floor or sustained superiority over Linux.

The native executor uses the public kernel-example bootstrap, a privately owned
ELF memory model, and null host signal/timer bridges. HVF uses the actual runtime
and carrier. Dependencies are locked separately and recorded in the manifest.
Consequently the difference is between these complete execution slices; **it is
not a causal measurement of HVF exit latency alone**. Required current-carrier
services may consume part of the available gain when integrated.

File setup, output and event draining are outside the guest timing window.
Timed phases contain no write/seek workload. This controls that component out;
it does not claim macOS filesystem parity. Raw Linux comparisons remain visible.

## What changed and what the experiments ruled out

1. Built a small whitelist-based AArch64 executor with private JIT publication,
   a register-preserving gateway, real ELF control flow and real SVC arguments.
   SVC uses current policy/interceptor/observer preparation and kernel dispatch.
   The old DSR identity/bias memory and one-host-process-per-guest models were
   not restored. Unsupported operations fail closed.
2. The first executable version returned to Rust on every backward edge. It
   measured 180 ns per integer iteration and 736 ns per memory iteration.
   A deterministic red test recorded 1025 callbacks for a 1024-iteration loop.
   Native bounded backedges reduced this to at most five; PC-relative address
   materialization also became native. This moved the actual compute pole.
3. Allocation measurement then found **4N+2 allocations per invalid loop
   window**, at N=1/8/32/128. LLDB traced both allocation sites to `current_mm()`:
   `MemAuthority::snapshot_until` and `snapshot_token`'s Arc allocation. The
   experiment only needed execution identity at that boundary.
4. Added `KernelContext::validate_current_execution_mm`. It invokes the same
   exact live-task, thread, registry, MM and execution-lease authentication without
   constructing mapping snapshots. Its return value grants no byte-access or
   code-publication permission. The experimental backing still enforces those.
   All four warmed allocation windows are now zero; no signal check or observer
   was removed. This is the only production API addition in this slice; it is
   not yet used by a product execution lane.

The remaining memory cost is concrete: each guest load and store still traverses
the checked Rust gateway. The native-only prototype is therefore unsuitable for
the memory traffic in Node, Go or Python, even though the watch loop improves.
Integer code also needs compact, linked blocks instead of the conservative fixed
instruction slots used to establish this experiment.

## Correctness and structural evidence

- Seven executor tests pass, including actual register/SIMD/NZCV preservation,
  virtual TLS, bounded backedges, wrong-publication rejection, same-VA private
  backing isolation, RX/W+X permission rejection and code revocation before resume.
- Twenty-nine kernel MM-access tests pass. The new identity API rejects the same
  wrong-thread, wrong-MM and same-numeric-identity foreign-kernel leases as
  `current_mm`. A live backend counter proves zero snapshot calls at all four
  scales, with `current_mm` as the positive control.
- Two contract-verifier negative controls pass. They continue to reject unbound
  native evidence and missing zero-work metrics.
- Same ELF fixtures validate actual EBADF returns, stable unchanged watch IDs,
  exact queue size, every drained `IN_IGNORED` record, and the overflow marker.
  All final native syscall populations and observer request/return totals are
  exact; the exit syscall correctly has no ordinary return.
- A separate allocator-instrumented build records exactly 2N requests and
  completions and zero heap allocations in each of nine warmed invalid-pair
  windows at N=1/8/32/128. Its positive control fires. It supplies no timing claim.
- Four typed `ContractObservation` files retain that partial evidence. They are
  deliberately **Incomplete**, not accepted embed observations. No live HVF-exit
  counter is fabricated; that metric remains unknown. Normal native linkage is
  recorded separately and has no Hypervisor.framework dependency.
- The experimental crate passes Clippy with warnings denied and formatting.
  Root MM tests and verifier tests are recorded; full CI and signed promotion
  were not run for this unaccepted execution prototype.

## Next implementation boundary

Implement native guest load/store lowering under **current-carrier backing,
permissions and generation authority**, then repeat these same fixtures. Required
red controls: two MMs at the same VA, stale ownership, cross-page permissions,
COW, in-place code writes, unmap/mprotect/exec and foreign-write revocation.
Code-link publication must share that authority; a guest address cannot become a
host pointer merely because a cached translation exists.

Then bind actual migratable task state, signal delivery/cancellation and concurrent
scheduling, and run signed embed plus full inotify09 and language controls. Keep
the direct host-file path and separate native macOS I/O control. Near-1x across
representative workloads remains the goal, not completion inferred from this
watch-only win.

Promotion is stopped by a measured result, not a missing permission: the
[conformance-contract skill](../../../../.agents/skills/carrick-conformance-contract/SKILL.md)
requires stopping promotion when “a valid completing workload is at least 10x
Docker.” The memory control exceeds that threshold, and current-carrier binding
obligations also remain open.

## Guidance and provenance

The experiment separates interception, guest compute and memory costs, following
the distinction in gVisor's Apache-2.0
[performance guide](https://gvisor.dev/docs/architecture_guide/performance/).
The BSD-licensed DynamoRIO
[AArch64 design documentation](https://dynamorio.org/page_design_docs.html)
is guidance for subsequent linked-block and register-state work. Pinned source
commits and file-specific license receipts are in
[`../permissive-guidance/sources.json`](../permissive-guidance/sources.json).
No third-party implementation code was copied into this experiment.

`manifest.json` records source hashes, toolchain, image, SHA-256, CDHash, UUID,
entitlements and HVF DOF. Final native binary:
`9f05321d6b75403637c7d0123216ef82a54acf6786e8d654f91af624d22b83c9`.
Final allocation binary:
`c55a4fa9405b4c7aa139189a65796dbbc45c8822390a6231fdc498cb61aa1cc8`.
Frozen and still-installed CLI:
`c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0`.

Executable copies and full source snapshots remain under
`target/lease-cost/native-slice`; selected raw evidence and all final cohort
receipts are durable beside this report. The initial failed allocation runs and
the debugger capture are preserved, not overwritten by the fixed result.
