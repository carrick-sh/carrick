# Incarnation-bound cancellation and host requests

Base `dc14f4f9e`, branch `integ/batch3`. Controller A remains unaccepted.

Three red-first reductions:

- An OnCpu cancellation returned El1Held without recording cancellation.
  If handback ran before the host follow-up, it returned HandedBack rather
  than Retired. Cancellation intent now precedes the ownership decision.
- A cancellation admitted by live() could be descheduled, then write a
  boolean into a reused slot. The replacement became cancelled. Request
  words now carry the original incarnation; a monotonic atomic publication
  cannot target a replacement or overwrite its newer request.
- Record incarnation wrapped at u64::MAX. That would invalidate tagged
  request ordering. The exhausted index now stays retired instead of being
  reallocated under an old identity. This does not change 32-bit park
  sequence wrapping; that separate CAS-authentication question remains open.

The first two witnesses model the exact split in the former cancellation
adapter. Its second request_cancel write is removed. The record's private
request type is shared by cancellation and host-wanted requests; clearing
remains an owner operation. A positive control verifies that an older
publisher cannot mask a newer cancellation or host request. The shared ABI
hash includes HOST_REQUEST_PROTOCOL, and the request storage is now 64-bit.

Validation: core62, EL1 host74, ABI32, kernel/semantics2459 (one existing
ignore;21binaries), kernel serial109 (four nested child runs), runtime630
(eight existing ignores) passed. Affected all-target Clippy with warnings
denied passed; registry68 passed. Red logs are retained alongside green logs.
No fresh signed execution or timing claim is made for this source.

Post-publication retirement/service-adoption ownership, complete context
restore proof, park-sequence wrap, exact scheduler wakes, deterministic signed
bindings and WorkObservation remain open. Historical Python/otmp attribution
and full batch acceptance are not implied by these reductions.
