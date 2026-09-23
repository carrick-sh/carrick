# Native adapter authority checkpoint

The descriptor now loads as kernel.execution.native-synchronous-syscall.
The registry had previously failed TOML parsing because structural_budgets was
placed as a note in bindings.unresolved. It now contains real embed-structural
budgets: zero HVF syscall exits, zero host heap allocations in the warmed
operation window, and at most two kernel dispatches per invalid-inotify pair.
Exact request/completion cardinality remains a required semantic assertion.
All execution bindings remain unresolved. No native observations are accepted.

`cargo test -p carrick-conformance-contract --tests` passes. The accompanying log
includes verifier negative controls that reject unbound errno-only evidence,
empty evidence, missing counters, one HVF exit and one host allocation. Synthetic
observations in those tests are explicitly verifier inputs, not experiment data.
This repairs the gate; it is not a red/green native implementation test or a
performance improvement.

## Instruction reader constraints found in live source

- kernel/mm_access.rs CurrentMm holds a snapshot token and a context lifetime.
  KernelContext::current_mm authenticates the supplied execution lease on entry,
  but the returned type does not borrow that lease. Do not store this token as
  continuing translation-cache execution authority after lease transfer.
- MmToken::read_range authorizes readable VMAs in its captured snapshot; it does
  not establish executable permission or current instruction bytes. Execute-only
  memory and readable non-executable memory require distinct handling.
- Aarch64EngineCore::read_bytes_raw uses live per-page translation and backing
  reads, including deferred private-file data. It is a syscall/core backing
  reader, not a complete executable fetch capability. Passing it alongside an
  independently supplied CurrentMm would not prove they name the same MM.
- The reused DSR planner already accepts a reader closure. Integrate at that
  seam only once the concrete engine binding authenticates the same live MM,
  execution lease, mapping permissions and frame-owner generations.

The first adapter must keep the lease borrowed through instruction fetch and
translation publication, bind the backing reader inside the authenticated engine
rather than accept an unrelated GuestMemory, and reject changed executable
mapping/backing generations before publishing cached code. Cached execution also
needs revocation for mprotect/unmap/exec and executable writes. A snapshot-only
execute-range helper would not satisfy this obligation.

Next implementation proof: two live MMs with the same guest VA but distinct
instruction bytes; wrong binding and stale lease rejected; execute-only accepted,
non-executable rejected; cross-page fetch validates every page; mapping or backing
changes between read and publish reject publication. Then actual translated guest
execution, memory/TLS/signals and syscall completion. No current source or timing
receipt demonstrates those native proofs yet.

## Implemented instruction-read prerequisite

KernelContext::fetch_instruction_bytes now authenticates the exact execution
lease, validates executable (not readable) permission across the entire range,
and reads through the carrier endpoint installed on that MM. It checks the
transport receipt and reauthenticates the mapping snapshot after the read.
InstructionRead retains both the context and execution-lease borrows. Its
validate_mapping method rejects changed backend, VMA or inventory revisions.
It is deliberately not a code-cache publication or execution permit: ordinary
in-place executable writes still require invalidation and publication integration.

The new unit tests exercise policy and delegation with the existing mock carrier
transport. They do not prove real carrier instruction fetching, two-MM byte
isolation, DSR execution or speed. The initial red log is an absent-API compile
failure, not a demonstrated pre-existing Linux semantic regression. No signed
binary was rebuilt or performance result changed by this work.

Next: qualify this reader against the real carrier endpoint (including two-MMs
at the same VA and execute-only backing), then connect the planner closure while
implementing executable-write invalidation and atomic cache publication. Deferred
execute-only backing is not yet qualified; the carrier's existing deferred-read
fallback is based on readable ranges and may reject it. Do not broaden readable
permissions to conceal that distinction.

## Carrier transport qualification

Added two tests against CarrierForeignMmTransport, using fixture-owned host
backing and software stage-1 tables (no guest and no hv_vm_create). Identical
VAs in two execute-only MMs return their distinct bytes with authenticated read
receipts. The sparse execute-only test initially failed with Translation at the
first unmaterialized page. That is a behavioral red, unlike the earlier API red.

The transport now permits its deferred backing lookup to use the authenticated
executable range as well as the readable range. Kernel data reads continue to
validate Read permission; kernel instruction fetch validates Execute permission.
The transport does not grant guest-readable permissions. For execute-only data
without a stage-1 translation, a retained exact-MM pristine recipe is required;
absence of a recipe fails instead of inferring instruction bytes. The kernel
reader continues to verify its receipt and before/after snapshot identity.

Both new transport tests pass, including refusal after recipe removal. All seven
existing foreign_mm_read tests pass (stale revisions, missing/reused owners,
sparse backing and mutation-coordinator deadline). Logs and source hashes are
retained here. These tests qualify the production transport with fixture backing,
not the composed KernelContext-to-carrier path or real guest instruction execution.
Private-file execute-only backing and cross-page executable permission boundaries
still need dedicated coverage. Publication, executable-write invalidation and
DSR memory lowering remain open; no performance result changed.

## Composed kernel and production-carrier check

vcpu_loop::memory::tests::instruction_fetch_composes_kernel_lease_and_production_carrier
passes. It uses real_production_cow_fixture: the kernel task graph, scheduler
execution lease, dispatch VMA authority, Stage1MmLease backend, kernel-minted
mapping/frame identities and ProductionCarrierForeignCowHarness together.
No mock byte transport sits between KernelContext and CarrierForeignMmTransport.
The backing and stage-2 map operations are fixtures; no guest instruction executes.

The test proves readable/NX fetch refusal, execute-only fetch of the installed
bytes, continued refusal of a data read through MmToken, cross-boundary refusal,
wrong-task execution-lease refusal, and invalidation after VMA permission change.
This closes the earlier composition gap for resident backing, not native execution,
JIT coherence or signed acceptance. Only this focused new test was needed/run;
no production path changed this turn.

## Existing publication seam, qualified by implementation

ForeignInstructionPublicationPlan authenticates an exact MM, binding, three
revision domains and byte range, and requires publication when a write intersects
an executable VMA. The carrier's CarrierForeignPreparedWrite::commit currently
copies bytes then invokes sys_icache_invalidate. This is hardware instruction
cache coherence; it does not invalidate translated blocks or advance a DSR code
generation. Reuse this exact write classification when attaching translation
invalidation, but do not treat the existing publication flag as a DSR cache proof.
Guest stores and other kernel writes still require separate coverage, including
writes via aliases that are non-executable in the writer's MM. Invalidation must
precede stale translated execution, not merely update a counter after a write.
