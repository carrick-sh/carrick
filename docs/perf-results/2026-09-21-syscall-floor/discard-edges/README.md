# Unaligned discard interior retirement: measured candidate

Node original app-smoke, two warmed ABBA blocks, untraced guest whole-process
wall time, no competing build/Docker lane:

- Control: 245, 245, 243, 241 ms (mean 243.5).
- Candidate: 185, 178, 185, 188 ms (mean 184.0).
- Candidate/control 0.75565: **24.4% less runtime**.

Matched release sources differ only in whether HVF advertises its anonymous
retirement granule (None versus 16 KiB). Preserve source manifests and signed
artifact identities; no historical percentage gains are compounded here.
Original Node workload and completion marker unchanged. Warm samples retained.

Go cold build ABBA: control 1.329/1.319 s, candidate 1.316/1.331 s (ratio0.9996).
Python OS ABBA: control2.659/2.551, candidate2.548/2.539 (ratio0.9764). These small
screens show no measured slowdown, not broad regression assurance or a confirmed
Python gain. Fresh original-fixture Linux Node 49/48/49/49 ms, candidate raw
mean ratio **3.7744x**. No I/O adjustment; not a parity acceptance result.

## Implementation and proof

HVF advertises its supported retirement granule. On an unaligned eligible
private-anonymous request the shared engine retires the aligned interior through
the existing stage-1/TLBI/alias/fresh-zero path, then authenticates and scrubs the
partial edges. Edge COW cannot invalidate an outstanding retirement ticket
because the interior commit precedes it. Edge errors after publication remain
indeterminate; refusal without an interior or backend support remains unmodified.
Other backends default to no opt-in.

The orchestration was red first (two failing behavioral tests against whole-range
delegation); all62 aarch64 unit tests pass after implementation. The boundary
contract checks actual scripted zero_backing bytes across16 boundary combinations
and scales1/8/32/128, bounded at24576 bytes independently of interior size.
Injected errors at first/second edge are indeterminate. This scripted proof does
not model real COW allocation or physical owner-generation failure.

Signed embed fixture passed16 fork cases: four offsets at four scales, writable
and read-only ranges, full neighbor checks, live peer original bytes, repeated
discard after rematerialization. Same-source native ARM64 Docker produces the
same four success rows. The semantic fixture is preservation coverage, not a
claimed semantic red on the old correct-but-slow implementation. Negative
entitlement control and scoped cleanup pass. Signed receipt preserved; test
source was only rustfmt-adjusted afterward (pre-format source also preserved).
Registry tests and changed-file formatting pass; this is not full CI.

The independent five-iteration minimal-child census closes212 requests/args/ends.
Explicit physical scrub drops207,872,000 to614,400 bytes total, or41,574,400 to
122,880 bytes per run (99.70% reduction). Each large request reports24576 scrub
bytes although the helper requests8192 edge bytes. The initial reader incorrectly
asserted equality with helper bytes and failed; the raw trace remains authoritative.
Backend preparation adds work beyond the helper counter; attribution of that
extra work is open. Do not claim total allocation zeroing or all COW work vanished.

## Still open

Real-carrier failure injection across interior preparation/publication/commit and
edge COW, backend compile matrix, full signed probe/smoke/ecosystem promotion,
concurrent scaling, and broader common-syscall floors remain incomplete. No commit
or push. Goal active. Candidate remains an experimental measured change.

target/release/carrick restored byte-identical to frozen candidate after control
build; no re-signing. Frozen convenience copy is
/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-edges.
