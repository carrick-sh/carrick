# Core reads under the capture exclusion (#1733)

The applicable contract is `kernel.mm.address-space-occupancy`: Linux core
contents and registers must describe the same paused address space. A gate
held by that capture is not an independent producer to await. Releasing the
capture pause to wake its own read loses that snapshot's authority.

`ThreadedEngine::read_core_bytes` now receives the exact guard's borrowed
`ExcludedEditor`. HAL owns chunking, incarnation validation, pristine backing
fallback and rejection of a read suspended on that same excluded Gate. The
AArch64 and x86 engines provide stage-1 output and backing-copy hooks. A core
read does at most one translation and one backing read per page fragment;
there is no owner-transfer retry or release/reacquire cycle on this path.
A capture with no published editor keeps its independent owner-wait path.

The VM-free `CrashCaptureTestEngine` witnesses distinguish those cases:

- `core_read_uses_capture_exclusion_without_reentering_its_gate` first observes
  an ordinary owner read refusing on a real raised gate, then requires a core
  read to return the bytes while that gate stays raised.
- `capture_core_reads_through_its_own_pause_gate` enters the production capture
  operation with a published MM. Its backend verifies that each core backing
  read is under the gate and that an ordinary read would refuse there. The
  operation produces both expected extents and releases its gate on return.
- `capture_core_gate_busy_once_then_reads_after_owner_release` retains a wait
  on an independent producer. It recaptures an altered prefix under a fresh
  snapshot after that producer releases; it does not reuse stale extents.

The x86 `core_snapshot_uses_shared_policy_and_translates_every_page` witness
enters the production `X86EngineCore` method across three fragments with
identity/private-overlay/identity outputs. It checks all returned bytes and
rejects an exclusion for a different MM. These are component proofs; they do
not execute guest instructions or establish signed crash acceptance.

The read witness was also transplanted onto admitted main
`ddadf2b523b51d309af582d5cda1901a46e08c24` in a detached checkout, with no
production changes. The only fixture adaptation used the existing
`CopyoutOwnerProbe::new` constructor because its fields are private there.
It executed one test and failed with `ReadSuspended(... cause: Gate ...)`:
zero passed, one failed, 747 filtered out. This is core-read red evidence,
not the outstanding signed refill red/green proof. After correction, all nine
focused `core_` runtime tests and the x86 production-entry witness passed.
The read-only independent review of correction `92c5bc875` found no outstanding
P0/P1 findings; it did not run tests or review the complete inherited stack.

The strengthened signed refill witness, signed Python fork/subprocess and Go
workloads, paired crash-population evidence, and attribution of the original
crash from a published signed core remain UNRUN (director). On this Linux
runner the signed entry point reports `macOS/HVF only` before running tests.

## Portable verification in this continuation

The regular/`serial_host` library partitions passed: AArch64 131/3, HAL
227/0, kernel 2818/195 (one existing ignored regular test), MMU core 269/0,
and x86 79/0. Zero serial cases means that crate defines no tests matching
that partition; it does not stand in for a runtime gate.

The justfile's prescribed full serial runtime recipe passed 744 tests with
six existing ignored tests. An earlier parallel invocation was invalid for
this crate: its process-wide lifecycle guard rejected an overlapping prepare
test (649 passed, one failed, five ignored). This rejected invocation is
retained in the evidence; serial execution is the existing required recipe,
not a production workaround introduced by this change.

`just build-cpl0`, `just check-linux`, `cargo check -p carrick-vmm-kvm`,
formatting, diff whitespace and the contract-change check against admitted
main passed. The built `carrick-xtask authority-debt --source-only` checker
and its admitted-base comparison passed with 1266 source counters.

The full `just cross-check-macos` (all-target compile and Clippy), host
`just clippy`, and both `just xtask authority-debt --source-only` invocations
(with and without the admitted base) subsequently completed successfully.
Embed unit tests passed 118 regular cases and defined no serial cases.
After the final test-only proof-lifetime edits, the nine runtime core cases
and x86 production-entry case passed again. A confirming independent code
review of `395092309` found no outstanding findings.

Earlier compiler commands were interrupted after sustained runner
filesystem-journal I/O stalls. Their logs remain separate; success is based
on the completing sequence, not those interrupted commands. No guest test
verdict was retried to obtain success.

Signed and Docker execution are unavailable on this Linux runner (Docker
executable absent). KVM is accessible, but its runtime merge-queue gate was
not run. Whole-workspace lint-domains and test-kernel were deliberately left
to CI. The signed acceptance requirements above remain open.
