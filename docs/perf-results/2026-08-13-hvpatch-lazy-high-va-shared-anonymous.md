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

## Review-fix addendum: advisory hint, descendant ownership, exact fragments

This addendum supersedes the original final-probe and cleanup receipts above.
Review found that the first probe used `MAP_FIXED`, that the backend alias
scope was still inferred from the current process bank, and that the backend
registry deleted whole alias entries on an overlapping unmap. Those were real
gaps even though the one-generation differential matched.

The corrected probe now passes the high address as a genuine Linux advisory
hint. Its flag word is only `MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE`; it
does not contain `MAP_FIXED`. Carrick honors the same selection path for the
high shared-anonymous `PROT_NONE` reservation and commits it lazily on
`mprotect`. The existing private high-hint cases remain alongside it.

### Corrected ownership model

The live backend registry now represents ownership explicitly as one of:

- `Root`, for root-address-space aliases;
- `ProcessBank { base, size }`, for one Linux process address-space lineage;
- `Global`, only for existing VM-global shared mappings.

A child fork inventory is assembled from the parent's authoritative aliases,
then inherited non-global aliases are rebound to the child's bank only after
all fallible child setup succeeds. A grandchild therefore discovers the
child-published alias, reuses the same `SharedAnon` backing identity and
physical extent, and remains invisible to unrelated banks. This is lineage
reuse, not VM-global identity.

The registry also separates each live semantic fragment
`(VA, IPA, host address, size)` from its backing's full physical extent.
Prefix, middle, and suffix unmaps split exact live fragments. A suffix advances
VA, IPA, host address, and shared-file offset as appropriate; both survivors
retain the same physical extent and inventory identity. Fork materialization
therefore deduplicates and maps that full physical extent once while the
semantic inventory remains exact.

### Review TDD RED

The focused tests were added before their production fixes and failed for the
reviewed reasons:

```text
RUST_TEST_THREADS=1 cargo test -p carrick-runtime shared_anonymous_high_advisory_hint_is_selected_then_committed_lazily -- --nocapture
FAILED: returned 618475290624, expected advisory hint 21451462672384

RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf fork_shared_anonymous_alias_survives_a_second_fork_without_global_scope -- --nocapture
FAILED: left 0, right 1

RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf alias_registry_partial_unmap_preserves_exact_live_fragments -- --nocapture
FAILED: left 0, right 2

cargo test -p carrick-cli --test trace_profile hvpatch_alias_sharing_ -- --nocapture
FAILED: hvpatch_alias_sharing_trace_fails_closed asserted that `walks = 0;` was absent
```

The first failure proves the runtime selected its shared aperture instead of
the requested high advisory address. The second proves an inherited alias was
lost at the child-to-grandchild boundary. The third proves an overlapping
unmap removed the whole backend registry entry instead of preserving two exact
fragments. The fourth proves the original DTrace program did not even inventory
the required companion walk, so its completion contract was incomplete.

### Review focused GREEN

```text
RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
132 passed; 0 failed

RUST_TEST_THREADS=1 cargo test -p carrick-runtime shared_anonymous_high_advisory_hint_is_selected_then_committed_lazily -- --nocapture
1 passed; 0 failed

cargo test -p carrick-cli --test trace_profile hvpatch_alias_sharing_ -- --nocapture
2 passed; 0 failed
```

The HVPatch suite includes the grandchild identity/scope test, prefix/middle/
suffix split tests, and the middle-fragment forkability test through the same
physical frame. The committed raw focused output is
`2026-08-13-hvpatch-lazy-high-va-shared-anonymous-artifacts/focused-green.txt`.
Test-only follow-up `c707d7c55f46521a2aa622d8d580b91c8d32b0a2` also asserts that the
prefix-unmap suffix and suffix-unmap prefix each remain forkable through their
retained physical extent; the refreshed raw output is sourced from that commit.

The DTrace program now requires alias maps, guest faults, alias walks, fault
walks, and fault TTBR companions. Provider errors exit 3, incomplete target
exit exits 2, and timeout exits 4. The saved-capture validator rejects zero,
incomplete, provider-error, timeout, malformed, and missing-completion
captures. Its focused CLI test exercises each case. A live zero-event launch
was attempted with the verified `sudo -n /usr/sbin/dtrace` path, but this host
refused both DTrace `-c` execution and `-p` attach (`Operation not permitted` /
`failed to grab pid`); that host policy does not replace the executable
consumer fixture gate.

### Corrected signed differential and generated cleanup receipt

The signed release binary was built from review-fix implementation commit
`a5a940eff47b529936a02b1ba9a1d2904f9cbaa7`:

```text
SHA256 bcac19722f8b134261129fe655087d30d514df20d30a83b3bba60b317ddc0430
LC_UUID 054205DD-A5A1-3C31-B959-05D4895C5EC5
codesign com.apple.security.hypervisor=true
Mach-O __TEXT,__dof_carrick present
```

Exact serialized command:

```text
docker run --rm --platform linux/arm64 -v "$PWD/conformance-probes:/p" -w /p rust:alpine sh -ec 'rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 || true; cargo build --release --target aarch64-unknown-linux-musl --bin mmaptrimprotect'
probe SHA256 26e9ddb43520cceb6a839e02f14fac3ed2326e494133eaaea051703373dc6a77
CARRICK_EXEC_BACKEND=hvpatch CARRICK_PROBE_RECEIPT=/tmp/hybrid-task1-fix-evidence-cleanup.txt scripts/run-probe.sh mmaptrimprotect
```

Exact output:

```text
CARRICK_PROBE_RUN_ID=cr-53745-28369
CARRICK_PROBE_CLEANUP_RUN_ID=cr-53745-28369
remaining carrick procs (run-id cr-53745-28369) = 0
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
```

The generated harness ID and cleanup ID are identical. The receipt is no
longer bound to a caller label that the harness replaces.

### Full gate and raw artifact manifest

The first review-fix `RUST_TEST_THREADS=1 just ci` attempt reached the native
Darwin suite and failed once in the unrelated existing test
`dynamic_x18_publication_is_veneered_and_executes_against_the_thread_slot`
(`left: 0`, `right: 335544320`). No native-Darwin code changed in this task.
The exact test passed three consecutive serial resamples. A fresh complete
`RUST_TEST_THREADS=1 just ci` then returned zero, including runtime lib
`1564 passed; 0 failed; 5 ignored` and runtime integration
`296 passed; 0 failed`.

The committed raw artifacts and SHA-256 hashes are:

```text
ff5e007e817cc98724dd45d459a99b71b2e69cf695cf550d320f89cc2bad3ab3  binary-identity.txt
6343858f6a98b9e28e628ef958b6f24af15a804bdb31ede57d763aaa7582d427  cleanup-receipt.txt
319f87d3b39f1d7807fbac19ef8179fa9a25d34e1cb7af562c9a96c502593bfc  focused-green.txt
160a03dbc9bbed14a0545a58f61e915da46ba21f016571432367cd766ef45936  just-ci-initial-native-x18-flake.log
d9ddd417814e5b1ec1d8ea8dd14ac591d27f28225a4cc417d5cadd13736dbf09  just-ci.log
2334c79a9ed066ce2e957cca85976e56263953060606ef15a9d6c67ec6a48f55  native-x18-resample.txt
0e5f20979147015d74b6f7b3583e36b9e8a3ef2792823438598db3c6f801b6a6  probe-build.txt
64ad458a192c4316bf2b0567e2f6fd16176a0bb4baa29154ed7e2b76489f2517  probe-match.txt
```

All paths are under
`docs/perf-results/2026-08-13-hvpatch-lazy-high-va-shared-anonymous-artifacts/`.
The raw binary receipt includes the source commit and parent, full codesign
details, entitlement XML, LC_UUID, SHA-256, and DTrace DOF section. The raw
probe output and cleanup receipt carry the actual generated `cr-*` run ID.
