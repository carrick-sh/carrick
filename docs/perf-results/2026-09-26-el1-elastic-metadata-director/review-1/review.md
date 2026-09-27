# Review round 1: ae6c3a17b is not accepted

All eight original host commands have been independently rerun and exit zero. Both alignment and grant-sizing red programs reproduce on your clean final ae6c3a17b. This is review round 1 of at most 3. Same task, same conversation. The original outcome remains installed guest
metadata allocation, authenticated growth/return, and a genuine signed-ready
witness. Do not replace it with a host-only allocator.

1. Allocator Layout semantics and admission API safety. A retained unchanged
core screen returns remainder 32 for align=64. Size rounding is not pointer
alignment. Payload-only growth request also omits header/alignment overhead:
a 65536-byte grant cannot fulfill its 65536-byte request. Require real arbitrary
alignment, checked arithmetic and adversarial fragmentation cases. Public safe
APIs cannot dereference caller-supplied integer addresses or raw pointers with
no unsafe contract/lifetime ownership. The current first-fit scan within a bin
is not O(1); derive and assert actual work bounds instead of claiming them.

2. Real guest mapping, route and lifetime. Host grant currently only maps
stage 2, returns IPA as guest pointer, and handles HVC in the old HVF trap;
prove the active shared AArch64 engine route and kernel-only stage-1 mapping.
Use existing authority/owner-generation and transaction machinery. Avoid a
process-global HashMap detached from VM/address-space lifetime. Never deallocate
backing after ignoring failed unmap. Return/reuse aperture space rather than
advance NEXT_DYNAMIC_IPA forever. Denial, stale tokens, cancellation and failure
must leave a valid recoverable state, including host bookkeeping allocation
failure and failed return. Preserve non-executable metadata permissions.

3. Install the allocator into the actual EL1 allocation path with safe bootstrap
initialization. There is currently no GlobalAlloc implementation or installed
global allocator; a test-only direct MetadataStorage call is insufficient.
Do not alias Linux syscall 448 (process_mrelease) as a production test command.
Use an appropriate explicitly gated fixture/control mechanism.

4. Witness must really cross bootstrap and prove denial/return in the owning
carrier. Four 64 KiB allocations fit inside the 9 MiB bootstrap; the later
512 KiB allocation also fits, so it never reaches the denial failpoint. Force
actual growth without shrinking production bootstrap merely to make the test
pass. Scope counters/failpoints to the carrier, transfer snapshots if a child
owns the VM, and prove concurrent users plus pending host work. A failpoint
armed before growth must not accidentally deny the wrong phase. Do not report
signed results: director runs them.

5. Contract/evidence. structural_budgets=[] plus a prose O(1) statement does
not prove the required work bounds. Bind actual measured/search/admission/
split/merge/retained-byte bounds at1/8/32/128 and repeated return/reuse. Include
all new ABI layout/transport facts in the agreed handshake hash. Retain raw
red outputs and source/fixture identity; do not synthesize evidence.

Saved read-only source and two red screens are in integration commit8acb35b14
under docs/perf-results/2026-09-26-el1-elastic-metadata-director/in-progress-screen/.
Final-candidate reproduction and all eight verification logs are preserved in /tmp/el1-allocator-review1. The same failures remain in ae6c3a17b; fix production code and bind the regressions, not just these screens.

Re-run every original prescribed verification command and report accurately.
No signed guests/Docker/main/push. Preserve the original scope fence and read
AGENTS.md. Use the existing output contract. This is not authority to relax
first-touch budgets or broaden into unrelated cleanup.

Additional exact review facts: your README describes a BlockFooter, magic field,
512 KiB grants and six counter fields that do not exist in the implementation.
Rewrite it from source and actual evidence. The scale test currently asserts
capacity/counts but never counts free-list search or other work. Do not claim
measured O(1) from that test. Hypercalls restore the caller's prior DAIF, which
can already have IRQ masked; establish a safe protocol for that entry state,
not merely a comment that IRQs are unmasked. Keep corrections focused on the
original allocator/grant acceptance outcome.
