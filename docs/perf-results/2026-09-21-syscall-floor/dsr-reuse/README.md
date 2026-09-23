# DSR component reuse check against current Carrick

Source donor: 20add4f9f1138cbca98cc672182cb093d473ac72 (parent of the native
backend removal). Isolated research workspace: target/lease-cost/dsr-reuse.
No restored translator crate is a member of the product workspace or linked
into carrick-cli. Current carrick-abi/guest-mem/mem/host dependencies are used
by absolute paths; historical DSR core and AArch64 source are otherwise intact.
The research lockfile records fresh dependency resolution, not historical pins.

Results:
- cargo check -p carrick-dsr-aarch64: passes against current dependency APIs.
- Decoder tests: 16 pass.
- Block-planner tests: 53 pass.
- Emitter tests: 29 pass.
These are selected tests, not all 232 library tests. Emission tests inspect code;
they do not attest translated guest execution, runtime signals or current MM
semantics. One mapped_memory warning exposes an ignored return from the current
vDSO setter; that old memory implementation is not an approved adapter.

## Concrete reuse seam

block::plan_with_reader already takes a guest-instruction reader closure. Feed
it from authenticated current-MM instruction access instead of NativeMappedMemory.
Decoder classification and register virtualization can be reused behind that
seam. emit::EmitAddressMode currently supports only Direct and Biased. Neither
mode by itself represents today's live per-MM backing/generation authority.
The old NativeMappedMemory and process-global fork state must not be used as
current authority merely because they compile.

The next code change must add an explicit current-MM memory lowering/capability,
not disguise a host pointer as guest VA or use a dummy fixed bias. Required red
cases: identical guest VA in two MMs resolves to different private bytes; wrong
owner generation is refused; mprotect/unmap/exec revoke cached access; cross-page
access validates both pages; write preparation preserves COW and shared visibility.
Executable translation identity includes exact MM and executable generation.
Reuse the existing conformance observation interface for these proofs before
calling the new mode usable by guest execution.

Implementation order: instruction-reader adapter; memory-access lowering and
revocation proof; gateway TLS/signal/PC recovery; current kernel synchronous
request/completion; actual invalid-contract guest ELF; valid watch operations;
common language syscall mixes plus memory/compute/JIT controls. A correctness-
only slow memory fallback may bootstrap execution but does not satisfy the
performance goal. Its cost must be visible before architectural promotion.

A fixed-bias aperture may be considered only if a real current-MM projection
can prove alias/permission/generation invariants without restoring the retired
host-process model or eager per-MM backing. No such projection is established.

This reuse check changes the next action from rebuilding a translator to
adapting its memory authority. It proves no native guest execution, speedup,
absolute floor or near-parity. Logs, donor revision, resolved dependencies and
source hashes accompany this document.

Follow-on research: ../dsr-current-mm-planner records a new current_mm module
and current-kernel dependency added to this scratch workspace after the original
98-test reuse check. The original donor source hashes remain historical evidence;
the follow-on adapter and lockfile have their own snapshots and receipts.
