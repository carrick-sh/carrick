# Investigation evidence enforcement and write/seek pilot

The investigation CLI now requires an explicit capability decision. A VM-free
classification cannot reduce through a guest layer. Diagnosis consumes receipt
paths, not prose, and review consumes a validated JSON ReviewPackage whose claim
belongs to the measured contract and whose causal evidence references its receipts.
Legacy narrative-only investigations must be reduced again; they cannot be
promoted by adding an arbitrary review filename.

`investigate run-write-seek --output <new-directory>` builds and runs the
registered VM-free producer with conformance metrics enabled. It captures both
streams, executable SHA-256, source revision and a digest of tracked and untracked
crate/contract/build inputs. Dirty source is included. Diagnosis revalidates these
identities, fixture activity, layer, fixture identity, scale and typed evaluator
failure. A green run, missing binding, unknown measurement or changed output is
not red evidence. Receipts are local evidence, not tamper-proof attestations.

The receipt runner currently supports only this registered VM-free pilot through
the CLI. Other signed/guest producers need their own artifact and cleanup adapters;
unsupported receipt layers fail closed. The underlying capture API is a trusted
local tool, not a sandbox for arbitrary executables. Do not use it for guests or
process-spawning producers. The pilot's 30-second execution budget kills and reaps
the direct producer. Its build uses Cargo's ordinary lifecycle. No unattended
campaign budget/scheduler completeness is claimed by this change.

The pilot acquires a coordinator window around build and execution. Existing
coordination is cooperative. This change does not qualify arbitrary unmanaged
builds, timing measurements, or the coordinator's cross-process crash behavior.

## What the pilot proves

`kernel.fs.write-seek` drives the real kernel dispatcher with HostFsBackend:
create a regular non-append file, repeat write(64 bytes)/lseek(0, SEEK_SET), read
back the bytes, close and exit. Completion counts independently establish fixture
activity at 1, 8, 32 and 128 iterations. The execution-scoped metric
`host_write_position_queries` counts actual preparatory host SEEK_CUR calls at
both scalar-write query sites, and is disabled with ordinary conformance metrics.

The contract budgets zero such queries only for this offset-zero, unlimited-file-
size, no-sparse-extents fixture. This is an architectural work requirement, not a
claim that Linux mandates any particular host implementation. Linux write/lseek
semantics remain the return-value, offset and content authority. It isolates one
mechanism reported in inotify09's thread B; it does not reproduce the complete
inotify workload, prove the claimed 35-microsecond timing, or close its 2x gate.

Signed and Docker bindings are explicitly unresolved. The registry can describe
such reduction-stage contracts; evaluating an absent binding still returns
UnsupportedLayer. Do not treat registration or VM-free red evidence as signed
acceptance. Inotify's existing watch and readiness claims are corrected to their
real VM-free capability, with coverage marked bound rather than unverified HEAD
execution evidence.

## Review boundary

A proposed offset-query optimization must account for shared open-description
state, dup/fork aliases, append changes, seek beyond EOF, subsequent truncation,
finite RLIMIT_FSIZE and sparse extents. A boolean meaning 'never sought past EOF'
is not by itself proof that the current offset cannot exceed a subsequently
truncated length. Require semantic regressions for these transitions before
accepting the production correction. This investigation leaves that correction
unimplemented and preserves the pre-existing runtime work.

## Verification scope

The transition regressions were witnessed red before enforcement: prose evidence,
VM-free-to-guest escalation, and a nonexistent review package all incorrectly
advanced. The fixed tests reject all three. Receipt tests run a real local
producer fixture and reject changed source, altered output, inactive fixtures,
and green observations. These tooling fixtures are explicitly not the pilot.
The real pilot runs the kernel's write and lseek operations and reads actual bytes.

Pre-existing `sought_past_eof` fields/methods remain unused and produce warnings.
An existing temporary-borrow error in `with_recorded_fd_open_path` was corrected
by retaining the captured table while its path guard lives. This compile-only
repair remains alongside the user's existing uncommitted method.

The strict `check-contracts` promotion check deliberately remains red for the
new contract's missing embed binding. The descriptor loader can represent its
explicit unresolved bindings for investigation, but this work does not weaken
the strict promotion check or supply placeholder runner names to make it green.
