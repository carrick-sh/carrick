# Carrier data activation and measured entry cost — 2026-09-22

Real carrier data can now be prepared during COW mutation, retained as an
opaque pin, and activated only while borrowing an authenticated native execution
scope. Bounded native CPU accesses run after mutation exclusion ends, preserving
original COW backing. This is still an integration primitive, not a product
execution backend or an end-to-end inotify09 improvement.

The new measurement changes the next priority: ordinary scope entry is about
36 ns, but activating one unchanged resident page is about **1.46 us**, adding
about **1.43 us** at the larger scale points. Rebuilding snapshots and rechecking
page authority at every syscall boundary would consume the performance gain we
are trying to retain. The next task is to remove that repeated work from the
unchanged path before adding more translator functionality.

## What changed

`CurrentNativeData::prepare_for_execution` consumes the mutation-scoped grant
and retains an opaque owner pin. It exposes no pointer. `PreparedNativeData::activate`
requires a live `NativeExecution`, authenticates the exact kernel/task/MM and
actual mutation coordinator, census and pause barrier, and returns a non-Send,
non-cloneable `ActiveNativeData` borrowing both objects.

Activation checks current backend/VMA/inventory revisions, readable/writable
non-executable authority, exact live owner generation and host backing, the
protection tracker, and every crossed live terminal leaf and physical
translation. A saved COW receipt cannot authorize a store after read-only/COW
rearming. Pending control refuses activation; only scope exit acknowledges the
safe point. Lifetimes prevent scope release or duplicate mutable activation
while the active grant is still used.

HVF retains revalidation state only in a native-specific wrapper. Ordinary
prepared copies keep their prior owner-pin path without the two extra Arc
clones that an initial version of this change would have added. No default
backend, translator whitelist, backedge bound, timeout or contract budget changed.

## Measured intervention

One preserved release runtime test executable alternates scope-only and
scope-plus-activation arms. Each arm completes all requested entries; COW setup,
preparation and output are outside timing. The fixed range is one valid 4 KiB
page. Scale increases the actual entry count, not the size of the data range.
Nine pairs are retained per scale: **36 pairs and 6,230,016 successful activations**,
plus untimed warmup. All raw samples are in `cost-samples.json`.

| Scale | Entries per arm/sample | Median scope entry | Median with activation | Median paired addition |
|---|---:|---:|---:|---:|
| 1 | 4,096 | 41.9 ns | 1.686 us | 1.644 us |
| 8 | 32,768 | 35.8 ns | 1.463 us | 1.427 us |
| 32 | 131,072 | 36.0 ns | 1.460 us | 1.424 us |
| 128 | 524,288 | 36.1 ns | 1.464 us | 1.428 us |

The smallest scale includes startup variation (1.462–3.689 us with activation).
All samples are retained. The three larger scales range approximately
1.444–1.473 us. These are same-binary host fixture diagnostics, with the runtime
conformance-metrics feature disabled, not signed guest timing, Linux ratios or
workload acceptance. No filesystem I/O occurs inside the measured operation.
The scope-only arm removes activation, so this is an intervention measurement,
not an inference from how often a function occurs in a profile.

The first diagnostic incorrectly requested ranges beyond the fixture's 16 KiB
compound. It failed closed with `Unmapped` at the second scale. Its partial
output, exact source and executable remain under `incomplete-*`; it supplies no
completed timing result. The corrected sweep scales activation count over a
valid single page and completed without retries or relaxed authority checks.

## Verification and red evidence

- API red: missing `prepare_for_execution` only (`red-api.log`). With the kernel
  wrapper present but no backend validator, the actual production-COW fixture
  failed with `AuthorityUnavailable` (`default-refusal-red-clean.log`). Neither
  failure is presented as an old workload regression.
- Three composed activation tests pass. They include 169 actual native
  load/add/store operations across 1/8/32/128 scopes, COW source preservation,
  seven independent stale-state cases, equal-MM-number/wrong-census refusal,
  pending-control refusal, an actual drain failing while access is active and
  succeeding after exit, and activation under a fresh successor execution lease.
- Runtime memory: **26 tests pass**, including the existing current-MM,
  prepared-write, ptrace and COW cases. Both debug and the measured release
  executable passed. One nested subprocess check also passes; it is not counted
  as another independent test. The release-only diagnostic is ignored by the
  routine suite and was run explicitly above. Runtime quiescence: **27 pass**.
- `just test-kernel`: **2,375 pass**, zero failures, one existing ignored test.
  Four memory lifetime doctests pass, including the two new scope/duplicate-borrow
  refusals. The existing native-scope allocation contract remains passing.
- **20 unchanged ELF controls pass in each build**, plus 11 native unit tests
  in each build. Exact guest streams and the two debug executables are retained.
  All **40 invalid-call allocation windows** contain zero allocations. These ELF
  controls still use private backing and do not exercise this new carrier grant.
- Signed foreign-MM suite: **73 pass, one fails, one ignored**. The failure is
  the already-recorded `kernel.mm.fresh-publication-maintenance` scale-1 budget:
  `PageTableInvalidations=1`, maximum 0. The signed runner withholds its success
  receipt. Earlier before/after attribution remains in `../native-carrier`;
  this continuation neither fixes nor closes that failure.
- A separate signed carrier-lifecycle test passes, with the unentitled negative
  control and scoped cleanup reporting zero remaining processes. Its receipt
  binds SHA/CDHash/UUID/entitlement/DOF. It is not a native execution binding.
- Changed-package `clippy --no-deps` passes. The broad dependency lint remains
  blocked by six pre-existing `manual_is_multiple_of` errors in two AArch64
  files; their hashes match the parent archive. Formatting and diff checks pass.
  New test-only lint findings were corrected. The cost diagnostic's intentional
  debug-run refusal has one local lint expectation with its reason.

The initial signed commands named a feature the HVF crate does not expose;
those build failures ran no tests and are preserved as `*-invalid-feature*`.
The corrected runs use the crate's supported default configuration.

## Next bounded change

Keep `kernel.execution.native-synchronous-syscall` unresolved. Its descriptor
now names this evidence facet without registering a false execution binding.

1. Move complete revalidation to preparation or mutation boundaries. Re-entry
   should validate an authenticated generation tuple in constant work. The tuple
   must cover stage-1 permission/COW changes as well as backend, VMA, inventory,
   owner and binding changes; existing VMA revisions alone are insufficient.
2. Prove revocation red-first for fork rearming, permission change/restoration,
   remap/unmap at the same VA, foreign COW, owner replacement and exec. Preserve
   the exact running handshake and opaque owner pin. Do not infer authority
   from a counter that omits any of these transitions.
3. Add measured zero-allocation and zero-page-walk budgets for unchanged
   activation, then repeat this exact entry-cost intervention. This targets
   measured controllable overhead before broadening the native executor.
4. Carrier invalidation-ticket service, translated-code publication/revocation,
   signals/cancellation and scheduler integration still precede carrier-backed
   ELF and full inotify09 acceptance. Keep raw Linux ratios and the native
   macOS I/O control separate when those workloads are measured.

## Provenance and non-completion

Worktree: `/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick`.
No commit or push; unrelated campaign changes are preserved. The seven-file
continuation is captured in `implementation.patch`, `before.tar.gz` and
`source.tar.gz`, with hashes and parent checks in `manifest.json`.
`measured-source.tar.gz` holds the exact source used for the cost executable;
the final source differs only by the test-only lint expectation for its debug
refusal. The measured executable and both ELF executables remain under
`target/lease-cost/native-activation`; their hashes are recorded here.

The measured product CLI and earlier native release executables are unchanged.
No new inotify09 or common-workload speedup is claimed. Full CI, product probes,
smoke/full conformance, native signed execution and the overall 1x goal remain
unclosed. The new concrete finding is the approximately 1.43 us activation tax
that the next change must remove.
