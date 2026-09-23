# Scoped native execution admission — 2026-09-22

Native execution now owns its exact-MM census endpoint and running handshake
as one scoped capability. The bounded ELF prototype enters this scope for each
native segment and ends it at its existing checkpoint before semantic dispatch.
No mutation exclusion is held over native execution.

This is an integration prerequisite for the 1x goal, **not a new speedup**. The
prototype still uses private ELF backing. The existing carrier data grant still
borrows COW mutation authority; no raw-pointer lifetime or permission was
expanded in this continuation. No new release timing cohort was taken.

## What changed

- `SyscallDispatcher::admit_native_executor` binds the exact thread, execution
  generation, executor epoch and current dispatch MM. Its native census endpoint
  owns the running flag directly; registry replacement cannot hide it.
- `enter_native_execution` borrows the admission and execution lease exclusively,
  publishes running before checking pause/control, and returns a non-Send,
  non-cloneable scope. Entry does not acquire the census lock or mutation guard.
- A stop request is sticky and request-only. It cannot acknowledge a safe point.
  Scope exit clears running; only then can ordinary dispatch borrow participation
  or the owner consume a request. Pending control refuses native re-entry.
- The prototype returns from the existing SVC/memory/backedge checkpoint before
  dispatching, then authenticates the next scope. The instruction whitelist and
  the existing 256-backedge bound are unchanged. Unsupported carrier control
  stops the research runner; it is not treated as delivered cancellation or a
  Linux signal. The extra host return/re-entry is unmeasured and remains part of
  the future cost accounting.

The new public contract is `kernel.mm.native-execution-scope`. Its VM-free
allocation observation intercepts actual per-thread allocator calls, checks a
positive control, and requires zero allocations for N enter/request/leave cycles
after admission and warmup at N=1/8/32/128. Actual entered scopes and sticky
requests are checked separately so doing no work cannot pass.

## Red evidence and verification

The initial public-API test is red only on the two absent admission/entry
methods (`red-api-clean.log`); this is missing-capability evidence, not a
measured old workload defect. The earlier dirty red log also includes a test
observation API typo and is not used as proof.

Review then found that the mutable ordinary dispatch token could be replaced
with a different participation while retaining the private native running flag.
The exact substitution test failed against the first scope implementation
(`replacement-red-exact.log`, one test). Native entry now verifies the exact
native endpoint identity as well as the task/MM/lease. The earlier short-filter
run executed zero tests; it is preserved but supplies no evidence.

Final results:

- **2,375 tests passed** in `just test-kernel`, zero failures, one existing
  ignored controller-receipt test. This includes the new public contract.
- **Seven native lifecycle tests passed**: pause-before-entry, actual mutation
  drain refusal while running and success after exit, sticky interrupts,
  endpoint substitution, wrong/transferred execution authority, unwind cleanup,
  and simultaneous same-MM scopes at all four scales, including 128 readers.
- **Two lifetime tests passed**, with actual E0499/E0505 diagnostics preventing
  stop acknowledgement or lease migration while the scope is live.
- **20 unchanged ELF controls passed in each of the default and allocation
  builds**, covering invalid calls, unchanged watches, churn, integer and memory
  work at all four scales. Each build validates 200 complete guest records and
  exact syscall/completion counts. The allocation build observes **zero
  allocations in all 40 invalid-call windows**. These are debug functional and
  allocation runs, not timing evidence or signed embed bindings.
- Existing native executor tests: **11 passed** in each build. Runtime memory
  composition: **23 passed**; runtime quiescence: **26 passed**.
- Kernel/example and native all-feature lint checks passed. The wider example
  lint initially found two pre-existing `unwrap` calls in the prior watch-churn
  fixture. Their source hash matched the parent archive; fixed-size array
  decoding now preserves the same 16-byte-event checks without those unwraps.
  No conformance budget or semantic expectation was changed.

## Remaining work

1. Prepare carrier backing as opaque state outside mutation exclusion, then
   activate data access only while borrowing this exact execution scope. Check
   live mapping, owner generation and every leaf permission at activation. A
   retained pin, restored VMA permission or earlier COW receipt cannot authorize
   a store after fork re-arms COW.
2. Compose this scope with the real carrier's COW invalidation service, scheduler
   and cancellation/signal delivery. The direct exact-MM drain is proved here;
   this does not acknowledge hardware invalidation tickets or implement process
   fork, register/TLS migration, or signal handlers.
3. Bind translated-code publication and alias/foreign-write revocation before
   carrier-backed ELF execution, then measure identical controls and the original
   inotify09 workload. Keep raw Linux ratios and native macOS I/O controls
   separate. Do not grow the translator to avoid these integration obligations.

The parent `kernel.execution.native-synchronous-syscall` execution bindings
remain explicitly unresolved. No signed embed, Docker refresh, product
probe/smoke/full promotion or full CI acceptance is claimed. The earlier
fresh-publication-maintenance and inventory-drift failures remain unclosed;
neither was rerun or weakened here. Full inotify09 and Node/Go/Python impact
remains to be measured.

## Provenance

`manifest.json` binds this delta to the preceding native-admission checkpoint,
exact final source hashes, source archives, API and behavioral red receipts,
final observations, native diagnostic artifacts and unchanged ELF hashes.
The frozen release Carrick/HVF/native timing executables remain byte-identical.
The functional test waits for each exact standalone child to exit; no HVF or
Docker guest is launched by these runs. Work remains local and uncommitted.
