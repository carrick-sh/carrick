# HVPatch lazy high-VA shared-anonymous commitment

Date: 2026-08-13

Task: hybrid kernel Task 1

Base: `b59114bda8940e51ec96b838b853c8338ab1829a`

Implementation: `b7a8f96c197e6d5b3b03d2b5051ea0f371f95298`

## Result

The signed HVPatch backend now matches native arm64 Docker for a high-hint
`MAP_SHARED|MAP_ANONYMOUS|PROT_NONE` reservation that is committed writable by
`mprotect`, written in the parent, mutated after `fork` in the child, and read
again by the parent. The existing private-anonymous V8-shaped cases remain in
the same probe and remain green.

This is a correctness result, not a performance claim.

## RED-first receipts

All commands were issued from the repository root. `scripts/run-probe.sh` runs
the Carrick and Docker arms serially and gives the subprocesses its own scoped
run id; the supplied `CARRICK_RUN_ID` documents the calling campaign. Cleanup
used only `scripts/sudo/kill.sh <run-id>`.

The probe was built before the runtime fix:

```text
scripts/build-probes.sh
docker run --rm --platform linux/arm64 -v "$PWD/conformance-probes:/p" -w /p rust:alpine sh -ec 'cargo build --release --target aarch64-unknown-linux-musl --bin mmaptrimprotect'
just build
CARRICK_EXEC_BACKEND=hvpatch CARRICK_RUN_ID=task1-high-va-stage-20260813 scripts/run-probe.sh mmaptrimprotect
```

Initial signed binary:

```text
SHA256  fac946427eb5107658cf558264feeb824637d8f56b2dcc31f86736ba1eaadb72
LC_UUID 6613E2EF-4986-37B9-BED2-327EE70DB8FA
entitlement com.apple.security.hypervisor=true
```

Docker reached all three new stage receipts:

```text
hinted_high_shared_mprotect=ok
hinted_high_shared_parent_seeded=ok
hinted_high_shared_fork_visibility=0
```

Carrick printed `hinted_high_shared_mprotect=ok`, then took SIGSEGV on the first
parent write. Therefore the RED was after a successful `mprotect`, before fork,
and was not an entitlement or child-coherence failure.

The focused host RED was:

```text
RUST_TEST_THREADS=1 cargo test -p carrick-runtime lazy_high_va_commit_preserves_shared_reservation_provenance -- --nocapture
FAILED: lazy commit must retain MAP_SHARED provenance
```

Preserving `ProcMapSharing` and selecting host `SharedAnon` made that host test
green but did not make the external test green. A signed staged binary
(`cc2f3bf743c7b36de5d3afcef3faba66b761fc43385d1ec7027f7b2ecc1d5a9a`,
LC_UUID `B55B1FFF-1C62-30F2-B733-397728098970`) still faulted on the first parent
write. The durable tracer `scripts/dtrace/hvpatch-alias-sharing.d` then showed
ESR `0x92000045`, FAR `0x13828ed00000`, and an L1 translation fault: the host
mapping succeeded, but the process's live stage-1 tables did not contain the
alias.

After stage-1 publication was fixed, the parent write succeeded and the first
fork attempt failed closed with:

```text
hvpatch child stage-1 VA 0x13828ed00000 resolves to IPA 0x5888c00000, expected 0xa309000000
```

That second RED attributed the fork failure to a retired private alias row
being replayed over the new shared alias. It led to the live-alias inventory
filter; no fault fallback was added.

## Re-architecture rationale

`OwnedHostMapping::guest_shared` had represented two different policies:

1. whether a real host fork keeps one physical backing; and
2. whether HVPatch gives a mapping VM-global IPA/frame and shared-file futex
   identity.

The fix introduces an explicit HVPatch classification:

- `Private`: process-scoped IPA, private fork copy;
- `ForkSharedAnonymous`: process-scoped IPA, `SharedAnon` host backing, explicit
  child reuse of the same frame/backing identity;
- `GlobalShared`: the existing shared-file/shared-aperture global IPA and futex
  identity.

Thus shared anonymous memory remains visible across the related Linux fork but
does not borrow a shared-file key, global IPA, or global frame deduplication.
Unrelated HVPatch processes remain separated by bank-scoped alias lookup. One
HVF VM is retained; no bytes are copied and no private-backing downgrade is
used for the shared-anonymous fork.

The dispatcher now also has a separate committed host-alias range inventory.
A VMA can exist without backing while it is a lazy `PROT_NONE` reservation.
Only a successfully claimed and committed host-alias transaction publishes the
backing range; pending, installing, and aborted transactions do not. Partial
unmap or replacement trims the exact range and preserves both fragments. An
in-process fork clones this inventory, independently of later parent unmaps.

HVPatch mapping rows are lifetime owners, not live-map authority. Fork and
sibling-union construction accepts a dynamic row only when the scoped live
alias registry contains the exact `(VA, IPA, host address, size)` publication.
This prevents retired owners from overwriting the child's authoritative
stage-1 mapping while still retaining backing lifetime.

Finally, alias PTE publication now uses the edit-and-TLBI path. A lazy
`PROT_NONE` commit may have a cached invalid walk, so “brand-new VA” is not a
valid no-flush assumption.

## GREEN receipts

Probe corpus build:

```text
scripts/build-probes.sh
probes built: conformance-probes/target/aarch64-unknown-linux-musl/release (446 binaries)
probes built: conformance-probes/target/aarch64-unknown-linux-gnu/release (446 binaries)
probes built: conformance-probes/target/x86_64-unknown-linux-musl/release (442 binaries)
```

The bulk x86 build printed target-incompatible inline-assembly failures for
several AArch64-only probes before its per-binary fallback; the script exited
successfully and the required AArch64 `mmaptrimprotect` artifact was built.

Final signed build and identity:

```text
just build
SHA256  25c3eaf71f9f4f1422aa86c3da7fb7a19074bacead1e60e8feba5d51e65ad42d
LC_UUID ACF8571E-38DB-37E4-8478-1835F9CBEF61
codesign entitlement com.apple.security.hypervisor=true
source commit b7a8f96c197e6d5b3b03d2b5051ea0f371f95298
```

Exact final differential and cleanup command:

```text
CARRICK_RUN_ID=hybrid-task1-final2 CARRICK_EXEC_BACKEND=hvpatch scripts/run-probe.sh mmaptrimprotect
scripts/sudo/kill.sh hybrid-task1-final2
```

Output:

```text
MATCH mmaptrimprotect
  hinted_high_result=0
  hinted_high2_result=0
  hinted_high_shared_mprotect=ok
  hinted_high_shared_parent_seeded=ok
  hinted_high_shared_fork_visibility=0
  v8_readonly_page_errno=0
  tail_trim_only_errno=0
  large_reserve_errno=0
  untrimmed_control_errno=0
  hinted_high_live_mprotect_errno=0
  hinted_high_rw_roundtrip=0
remaining carrick procs (run-id hybrid-task1-final2) = 0
```

An earlier final candidate was also run twice serially and produced the same
line-exact MATCH, so the result was not a one-run fork accident.

Focused host gates on the committed implementation:

```text
RUST_TEST_THREADS=1 cargo test -p carrick-runtime host_alias_ -- --nocapture
13 passed; 0 failed

RUST_TEST_THREADS=1 cargo test -p carrick-runtime lazy_high_va_commit_preserves_shared_reservation_provenance -- --nocapture
1 passed; 0 failed

RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf fork_ -- --nocapture
14 passed; 0 failed

RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
128 passed; 0 failed
```

Full repository gate:

```text
RUST_TEST_THREADS=1 just ci
PASS: fmt-check, clippy, lint-domains, deny, check-matrix, check, doc, test, test-integration
runtime lib: 1563 passed; 0 failed; 5 ignored
runtime integration: 296 passed; 0 failed
```

The first final CI invocation also completed all test/doc phases green, but its
receipt wrapper assigned zsh's read-only variable `status` after the gate. The
command above is the clean rerun with an unambiguous zero exit.

## Files and review

Production changes span the dispatcher transaction/inventory, HAL sharing
seam, AArch64 stage-1 publication, HVPatch backing/fork inventory, and
observability needed for durable attribution. The conformance probe and DTrace
script are retained as regression and diagnostic artifacts.

Self-review found no private backing fallback, byte-copy substitute, or
shared-file/futex identity reuse. Failed backend installs cannot commit the
dispatcher inventory; partial metadata replacement is range-aware; private
fork mappings still request a distinct snapshot/frame; shared anonymous fork
mappings inherit the parent frame and unique anonymous backing identity. The
controller-owned `hybrid.md` change was neither edited nor committed by this
task.
