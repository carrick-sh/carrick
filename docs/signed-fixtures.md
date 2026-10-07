# Signed-tier fixtures without Docker

`carrick-xtask fixtures build --sha <full-HEAD-SHA>` builds on Linux, either
native AArch64 or an x86_64 host with `aarch64-linux-gnu-gcc`. It uses the
pinned Rust toolchain, both installed AArch64 Linux targets, and Rust's
self-contained musl linker. It never invokes Docker or executes guest code.
A native ARM Linux publisher can run exactly the same command.

## Inventory

The signed steps in `crates/carrick-xtask/src/accept.rs` consume:

| Consumer | Executable destinations | Builder |
| --- | --- | --- |
| `generic_probe_shard_`, `case_`, and retained probes in the full profile | `conformance-probes/target/aarch64-unknown-linux-{musl,gnu}/release/<name>` | Locked `cargo build --release --target <triple> --bin <name> …` in `conformance-probes` |
| `carrick-embed el1_` | `fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/<name>` | `scripts/build-linux-fixtures.sh`, raw `rustc --emit=obj` and static ELF linking; PIE declaration retains its static PIE shape |
| Embed interceptor, file-reader, icache, and EL1 scheduler bindings | `target/embed-fixtures/{interceptor-probe,zone-readers,icache-reuse,el1-sched}-aarch64` | The four `scripts/build-embed-*.sh` builders, local musl Cargo builds |

The bundle contains every non-excluded `conformance` and `helper` entry in
`conformance-probes/probe-inventory.json`, for both libcs. This includes
`probeinit`, the fork/exec transport helper. At introduction there are 530
names per libc, 68 raw fixture declarations, and four embed executables:
1,132 executable destinations. Restore derives the inventory from the
checkout rather than trusting this count or the manifest's claims.

`case_` scripts and Python fixtures are tracked source inputs, compiled into
host tests or run in the pre-existing guest image. Go workload fixtures,
`bench-native`, native-PIE probe variants, and x86 probes are not selected by
these signed acceptance filters. Guest OCI images (including Ubuntu and the
full profile's LTP image) are separate image-store prerequisites: this bundle
neither provisions nor authenticates them. The signed host CLI, EL1 payload,
and test executables are built and signed on macOS using the existing signing
scripts; they are not guest fixture outputs.

Previously the ARM64 closure probe builder used native ARM Docker containers
in `scripts/build-probes.sh --closure-arm64`; ordinary probe builds also used
containers on macOS. Embed and raw fixtures already cross-built locally, but
`test-signed.sh` rebuilt them before every embed invocation. The older
`provision` receipt is not an immutable executable bundle and omits icache
from its inventory. It remains a separate developer provisioning command;
it cannot authorize signed acceptance.

## Input identity

A bundle's **input identity** is the SHA-256 of its canonical source
inventory, its recorded compiler inputs and its build policy
(`Manifest::input_identity`, recorded as `inputs_sha256`). Canonical JSON
frames every path and digest as a quoted, escaped string. Restore and verification admit a bundle when its input
identity equals the checkout's current identity, whichever commit published
it: `source_head` is publisher provenance, not an admission key. An unrelated
commit, or unrelated dirty or untracked files, therefore keep the bundle
valid. Any change to a fixture input refuses it with `fixture input identity
mismatch`, naming both identities, the build commit and the differing inputs:
fixture sources, a crate in a fixture's path-dependency closure, a fixture
`Cargo.lock`, tracked Cargo configuration, the compiler pin, a builder script
or the publisher's own build code. A dirty or untracked fixture input is
refused before hashing. There is no hand-maintained crate list; the closure is
re-derived from `cargo metadata` on every check, so a new path dependency is
an input as soon as a fixture depends on it.

The source inventory is the union of two derivations:

- **Cargo graph closure**, re-derived on every check (below). It is resolved
  **unfiltered** by platform: build-dependencies and proc-macros compile for
  the publisher's host, which need not match the verifier's, so a guest- or
  host-filtered graph could omit a `cfg(target_arch = ...)` build helper.
- **Compiler-recorded inputs** (manifest v3 `compiler_inputs`). After
  building, the publisher reads every executable's dep-info (Cargo's
  `<bin>.d`; the raw builder emits `<name>.d` with `--emit dep-info`) and
  records each checkout file the compiler read: `#[path]` modules,
  `include_str!`/`include_bytes!` targets, build scripts and their
  `rerun-if-changed` files, wherever they live. Files in the locked
  registry/git cache and the pinned sysroot are identified by `Cargo.lock`
  checksums and the compiler pin instead. A generated file under any
  `target/` directory, a relative path, any other file outside the checkout,
  or an executable without dep-info fails the publish. Admission hashes every
  recorded input from the checkout; one that is missing, untracked, dirty or
  under `target/` is refused.

The inventory follows a **restricted dialect**: what the publisher cannot
prove is an input is refused rather than chased.

- **No symlinks on a compiler-reported path.** Each dep-info path is walked
  component by component as written, before any canonicalization; a symlink
  at any component (or a path reaching the checkout through an outside
  symlink) fails the publish. Recording a link's current referent would let a
  retarget keep the identity.
- **Build code.** Build scripts and proc-macros can read files dep-info never
  names, and an approved entry file can delegate to modules or
  build-dependencies. Checkout packages in a fixture graph may therefore not
  have a build script or be a proc-macro at all, and git or path build code is
  refused. Only locked registry build code is admitted: each must be listed in
  the committed `fixtures/reviewed-build-code.json` by package, version,
  source, kind and its `Cargo.lock` checksum, which pins the whole crate.
  Publish and admission refuse an unlisted, changed or stale entry; the list
  is itself an inventory input. `carrick-xtask fixtures build-code` prints the
  current set for review. The seeded list holds the build scripts of
  `crc32fast` 1.5.0, `libc` 0.2.186 and `libc` 0.2.189 (each reads only
  environment variables and the compiler version).
- **No linker inputs.** Linkers read files dep-info does not name and resolve
  them by their own search rules, and scripts or response files can pull in
  more (`INCLUDE`, nested `@file`). Fixture builds therefore use none: any
  linker-script or response-file reference (`-T`, `--script`, `@<f>`,
  `INCLUDE`, `*.ld`/`*.lds`, including inside `-Wl,` and `link-arg=`) in a
  builder script, an inventoried `.cargo/config(.toml)` or, at publish, a
  build-script `cargo:rustc-link-arg*` output is refused. Nothing is resolved
  or authorized.
- **No generated sources.** A compiler input under any `target/` directory
  (an `OUT_DIR` `include!`) is refused. No fixture uses one today; adding one
  needs a design change, not an exception.

Each source entry digest is SHA-256 over a domain naming the entry type
(`carrick.fixtures.source.v1\0regular\0`), the big-endian u64 length and
the bytes. Only regular files are inputs: a symlink anywhere in the inventory
is refused, so link text can never stand in for file contents.

## Bundle and restore

Build requires the full current HEAD SHA and clean fixture source inputs. It
builds in a fresh `git archive` snapshot: an old executable or Cargo target
cache cannot stand in for a fresh output. Cargo locks, Cargo configuration,
fixture sources, probe inventory, build scripts, and compiler pin are hashed.
For each fixture manifest, the source inventory runs `cargo metadata --locked
--offline --format-version 1` (no platform filter) against the fixture
manifest and follows its resolved dependency graph. Metadata runs in
an isolated directory with the checkout's tracked Cargo configs passed
explicitly in Cargo precedence order. It hashes the
tracked source trees of reachable local path packages, including transitive
and build dependencies; dev-only edges are excluded because these binaries
are built without tests. The inventory also includes each fixture
workspace's own `Cargo.lock`, ancestor Cargo manifests and configuration of
every reachable path package, the compiler pin, the shell builders and the
Rust publisher's build and probe-selection sources. Unrelated workspace crate
sources, such as `carrick-runtime`, are outside this inventory, and so is the
host workspace `Cargo.lock`: Cargo builds each fixture workspace from its own
lockfile and never reads an enclosing workspace's lock.

Build, restore, and verification need Cargo and cached registry metadata/source
packages for these locked graphs. Prepare a cold cache with `cargo fetch
--locked --manifest-path <fixture>/Cargo.toml` for each fixture manifest before
going offline. No cross compiler or guest target installation is needed just
to resolve metadata. Missing manifests/locks, failed resolution, or path
packages outside the checkout fail closed; there is no whole-workspace or
incomplete-inventory fallback.
Source symlinks are refused; executable objects and destination paths
reject symlinks too.
The manifest also records `rustc -vV`, Cargo, GNU linker identity, target triple
per executable, and SHA-256 of every executable. Builds check that the
checkout and snapshot still agree before publishing.

The default store is:

```
target/fixtures/bundles/<source-sha>/<manifest-sha256>/manifest.json
target/fixtures/bundles/<source-sha>/<manifest-sha256>/objects/<executable-sha256>
```

The content address hashes the canonical manifest bytes, which in turn name
all executable objects. An existing address is verified, never overwritten.
These hashes provide integrity and freshness, not publisher authentication:
transport bundles from the trusted build publisher.

Transfer the entire content-address directory, preserving executable modes.
On any checkout whose fixture input identity matches:

```sh
just xtask fixtures restore --manifest /scratch/bundle/<manifest-sha256>/manifest.json
just xtask fixtures verify
just xtask fixtures verify --manifest /scratch/bundle/<manifest-sha256>/manifest.json
```

Restore acquires exclusive host gate admission inside the Rust operation,
before validation or publication, and holds it through final verification.
An inherited gate lease is reused; an inherited shared lease is rejected
without attempting an upgrade. Standalone manifest and archive restores
therefore cannot replace fixtures used by a live signed gate.

Restore verifies the address, input identity, full source and executable inventories,
all hashes, executable permissions, AArch64 ELF architecture, static musl
shape, GNU loader, and compiler pin before writing any destination. Paths
outside the declared inventory and symlink components fail closed. It captures
and revalidates all objects in staging before publication. Individual files
are published atomically, and the installed receipt at
`target/fixtures/installed.json` is published last. An interrupted restore
has no acceptance authority; there is no promise of a multi-directory atomic
filesystem transaction. Verify always reads every installed executable again.
Publication performs one durability flush on the final receipt, rather than
one storage flush per executable. The `host.fixtures.publication` structural
budget is one flush per restore, independent of executable population; its
VM-free binding checks both 9 and 71 executable destinations. A receipt alone
never authorizes files after interruption or power loss: verification rehashes
every installed path and rejects missing or changed bytes.

Signed acceptance in both profiles records a fixture verification step and
fails before signing or guest execution if it cannot verify the installed
receipt and every fixture. `test-signed.sh` verifies again for embed and
conformance-next invocations; it consumes the restored bytes without building
guest fixtures. Both the installed receipt and fresh verification evidence
record `validation_method: "input_identity"`, the checkout's exact HEAD
(`checkout_head`), the Git tree of its working state (`checkout_tree`:
tracked and untracked files, gitignored outputs excluded, written from a
private copy of the index), the bundle's build commit (`bundle_source_head`),
checkout dirtiness, and the manifest and input-identity SHA-256 digests.
Acceptance includes this evidence as `fixture_validation`; signed-test JSONL
includes a `fixture_validation` record. These fields describe fixture input
equality, not full-tree SHA equality or acceptance of a dirty host build.
Receipts installed before `checkout_tree` existed no longer parse; restore
again.

## Controlled fixture build policy

The manifest records `build_policy`, and `inputs_sha256` hashes the
source inventory, recorded compiler inputs and that policy. Earlier manifests must be rebuilt; editing
a manifest cannot supply evidence that its executables followed the policy.
Verification requires the recorded policy to equal the current publisher's
policy and refuses ambient `CARGO_PROFILE_*`, `CARGO_BUILD_*`, target linker
or rustflag overrides, `RUSTFLAGS`, encoded rustflags, and compiler wrappers.
Move intended fixture settings into tracked Cargo configuration and rebuild.

Build and metadata commands clear the inherited environment. They retain only
`PATH` for tool discovery, put the pinned Rust toolchain first, and explicitly
set the Rustup location/toolchain, isolated `HOME`/`CARGO_HOME`, `LC_ALL=C`,
`TZ=UTC`, and `CARGO_NET_OFFLINE=true`. The publisher supplies the declared
musl/GNU linkers. The isolated Cargo home shares downloaded registry/git
inputs and their existing cache lock domain; it contains no user config.
Other ambient variables (including shell startup hooks and compiler flags)
are absent from compiler and build-script processes.

Metadata reads only explicitly selected tracked checkout configs. Builds run
in the fresh archive snapshot beneath an isolated temporary directory whose
ancestors must contain no Cargo config. Cargo-home and checkout-parent config
files therefore cannot change the effective build. Untracked or symlinked
checkout configs are rejected before Cargo runs. Toolchain and linker version
identities remain in the manifest; this is a controlled build-input policy,
not a sandbox for untrusted build scripts or a claim of bit reproducibility.

## Scoped tests and red-first work

A bundle stays valid across commits and dirty edits that do not touch fixture
inputs. Restore once, then commit, rebase or edit host sources freely; rebuild
and publish only when the input identity changes. For a runtime red-first test
on macOS:

```sh
git checkout <pre-fix> -- crates/carrick-runtime/src/<file>.rs
just xtask fixtures verify
just test-embed <focused-test-filter>  # rebuilds and signs the test executable
# Record the failing assertion, then restore the fixed version and repeat.
git restore --source=HEAD --staged --worktree -- crates/carrick-runtime/src/<file>.rs
just test-embed <focused-test-filter>
```

This example assumes the fixed version is committed at HEAD; preserve any
uncommitted work before replacing a file. The same fixture validation applies
to direct `scripts/test-signed.sh carrick-conformance-next <filter>` runs.
A modified or untracked input inside a fixture or its resolved dependency
closure still rejects the bundle. If the test changes such inputs, commit
that variant, build and restore its bundle, and test that artifact.
`just accept --phase signed` and `remote-accept` additionally require a
fully clean checkout. Acceptance checks tracked and untracked files
independently of fixture validation, overriding Git's untracked-file display
preference; only gitignored outputs are excluded. It checks again before
signed work and before issuing a PASS receipt. Its receipt binds the exact
HEAD, `checkout_tree` and the bundle's input identity. Focused dirty-tree
receipts do not confer acceptance or carry signed executable identity across
rebuilds.

## Remote acceptance and Actions entry points

The native ARM Linux publisher runs:

```sh
just fixtures-publish "$GITHUB_SHA"
```

It builds the exact commit and emits one content-addressed artifact under
`target/fixtures/published/<sha>/<manifest-sha256>.tar.gz`. Upload that file
with the Actions artifact service, using an artifact name containing the full
SHA. Transfer the archive intact: Actions artifacts discard ordinary file
permissions, while the tar envelope retains guest executable modes. The
publisher never replaces an existing artifact with different bytes.

After checkout and cleanup, download the same-run, exact-SHA artifact to the
Mac. Both restore and acceptance belong inside one exclusive admission:

```sh
just lease gate sh -c 'just fixtures-restore "$1" && just accept --phase signed' fixtures "$bundle"
```

`fixtures-restore` extracts only regular manifest/object files and their
declared directories into private staging, rejects links, traversal, duplicate
entries and multiple roots, then uses the same complete manifest verifier and
receipt-last restore as `--manifest`. Missing, changed or non-executable
objects and a bundle built from different fixture inputs fail before
acceptance. `just lease`
preserves command argument boundaries and accept inherits its existing gate
descriptor, without reacquiring or upgrading a shared lease. Upload the
fixture artifact separately from acceptance logs and receipts.

`just remote-accept --ref <sha> --phase signed` selects the unique local
`target/fixtures/bundles/<sha>/<digest>/manifest.json`, packages and transfers
it to that run's directory, and restores it after checkout cleanup. With no
bundle published from `<sha>` itself and the local checkout at `<sha>`, it
selects the unique stored bundle (under any build commit) whose input identity
matches the checkout. Supply `--fixture-manifest <path>` when the bundle is
elsewhere, the checkout is at another commit, or several stored bundles
match. There is no fallback to mutable local or remote probe directories, and
the gate host re-verifies input identity against its own exact checkout.
Host-only acceptance needs no guest fixtures.

Use `--remote-bundle /absolute/gate-host/path/bundle.tar.gz` to consume a
published archive already on the gate host instead of uploading a local
manifest. Gate-host preparation opens each source path component without
following symlinks, rejects non-regular files and `.partial-` publication
names, and copies the admitted file into the run's private `fixtures`
directory. Verification, SHA-256 hashing and restoration use only this
capture. Archive verification reads the gzip stream through EOF, validating
all member trailers and rejecting trailing garbage for local uploads too.
It then invokes the same checkout-aware verifier as manifest restoration:
v3 schema, input identity (scoped source closure), current build policy,
toolchain and executable inventory must all match before run provenance is
published.
Ambient build overrides are rejected here as well as during restore.
`fixtures verify --bundle <path> --receipt <path>` writes fresh input-identity
evidence atomically. Receipt annotation and attach preserve acceptance's
`fixture_validation` alongside the run's `fixture_bundle` transport provenance.
The independent fully clean-checkout checks in acceptance still apply.

Admission deliberately rejects symlinks in **every ancestor component** as
well as the final archive component. This keeps directory aliases from
redirecting a descriptor walk. Supply the physical directory spelling if a
store is reached through an alias; on macOS use `/private/var/...` rather
than `/var/...`. Admission does not canonicalize a supplied path or follow
its final symlink. The usual `/Volumes/...` store paths have physical
ancestors. Tests canonicalize only their temporary root before constructing
paths, leaving their own rejection-test symlinks unresolved.

Preparation atomically writes `gate-runs/<run-id>/fixture-bundle.json` after
verification and before restoration. It records the source kind and path,
captured path, manifest identity and archive SHA-256. Both fresh polling and
`--attach <run-id>` read this gate-host provenance to annotate the fetched
receipt. The gate also writes its receipt in the private run directory, so
reattaching after worktree reuse cannot fetch another run's receipt. Attach
rejects `--remote-bundle` and `--fixture-manifest`; the caller cannot attribute
a run to an unverified path. Receipts publish by temporary file and rename, and annotation errors fail remote acceptance.

Remote acceptance holds the checkout lock before acquiring one host gate lease
across restore, signed acceptance and scoped guest cleanup. It reinstalls the
complete bundle even on same-SHA reuse, so lost ignored outputs cannot be
mistaken for a valid previous receipt. Its preparation script fails if the
checkout lock is absent or a signed/all job has no bundle.

The existing trusted-hardware `kernel-runtime.yml` workflow publishes on
native ARM Linux and passes the same-run, exact-SHA archive to its dependent
HVF job. After checkout and artifact download, one exclusive host lease
covers restore, signing, embedded tests, cached probes and scoped cleanup.
Its VM-free regression executes that workflow preparation on an empty
checkout, repeats it after same-SHA raw-fixture removal, and rejects an
artifact built from different fixture inputs before either signed test
command can execute.

PR #2's merge-queue worker will replace `land-provision` with these publisher
and restore entry points after this PR lands, per director coordination. Its
workflow topology is not imported into this branch. That workflow must retain
its trusted-event guards, wait for the Linux publisher, download the artifact
from the same run, and perform restore after its own checkout cleanup.

## Contract and evidence

This is host-only acceptance/provisioning code outside guest execution. The
applicable invariant is exact source and executable identity for every signed
fixture, with work linear in input and executable bytes. No guest ABI, guest
scheduler, or guest-operation budget changes. The VM-free xtask tests cover
roundtrip installation, tampered/missing objects, manifest tamper, a checkout
HEAD differing from `--sha`, source drift, acceptance refusal of untracked host tests, controlled build
environment/config isolation and policy mismatch, unrelated dirty workspace
edits, direct/transitive path dependency
drift, failed metadata resolution, missing lockfiles, input-identity receipt
fields, incomplete/duplicate inventory, wrong targets/toolchain,
permissions, symlinks, and missing/tampered installed files. The initial
red-first CLI test failed with `unrecognized subcommand 'fixtures'` on
`6a33e26b2` (see the implementation commit for the exact base SHA).

Preparation bindings run real Git checkout/cleanup, the real just recipes,
mode-preserving archive transport and xtask restore/preflight on empty and
same-SHA reused checkouts, and reject stale-SHA artifacts. A full remote CLI
binding runs real Git and rsync servers through a local SSH transport; only
the physical network and HVF acceptance are replaced. The reviewed head
failed empty/reused preparation with `No such file or directory (os error 2)`;
the Actions entry point failed with `justfile does not contain recipe
fixtures-restore`. The full remote CLI control returned guest preflight exit
1 and could not fetch a receipt. Strict signed preflight remains unchanged.

Signed execution and Docker differential acceptance remain director-owned.
The worker proof transfers a real ARM64 bundle to a cloudmac scratch checkout
and runs restore plus verification without starting guests or using the gate
worktree. Remote gate receipt: `director-queued`.

The scope red witness `clean_restore_then_unrelated_edit_preserves_fixtures`
uses the publisher's inventory to create its bundle. With the legacy broad
inventory restored, it printed `clean restore succeeded before unrelated edit`,
then `introduced only crates/carrick-runtime/src/lib.rs edit`, and failed with
`dirty fixture source inputs`. Thus the red reaches the edit after proving
clean installation; independent-inventory tests separately verify the new scope.

The input-identity witnesses were added red-first against the exact-SHA
admitter: `committed_unrelated_edit_keeps_bundle_admissible_by_input_identity`
failed with `unknown fixture schema or wrong SHA`,
`workspace_lockfile_is_not_a_fixture_input` with `dirty fixture source inputs`,
and `bundle_selection_follows_fixture_input_identity_across_commits` with
`found 0`. `committed_fixture_input_edits_refuse_by_input_identity` (fixture
source, direct, transitive and build-dependency path crates),
`fixture_lockfile_change_refuses_by_input_identity` and
`toolchain_pin_change_refuses` were refused only by commit, never by input
identity; they now refuse with `fixture input identity mismatch`, as do the
remote-preparation and Actions workflow bindings.

A review of the first input-identity revision found three holes that exact-SHA
admission had masked; each was closed red-first. Against that revision,
`compiler_input_outside_package_directories_refuses` (a committed change to
an `include_str!`ed repo-root file), `symlink_with_identical_link_text_refuses`
(a regular file holding `actual.txt` replaced by a symlink to `actual.txt`)
and `target_cfg_build_dependency_is_a_fixture_input` (a committed change to an
x86_64-only build-dependency) each kept the stale bundle admitted. They now
refuse. `cargo_dep_info_records_out_of_package_compiler_inputs` runs a real
Cargo build and checks the recorded `#[path]`, `include_str!`, build-script
and `rerun-if-changed` inputs; `dep_info_classification_fails_closed` and
`recorded_compiler_inputs_must_be_tracked_sources` cover the refusals.

A second review round found three more holes, closed red-first in the same
dialect. Against `a4395e7e5`: `dep_info_refuses_compiler_inputs_reached_through_symlinks`
recorded only `shared/a.txt` for `shared/current.txt -> a.txt` (a retarget
kept the identity); `unreviewed_build_script_refuses_publish_and_admission`
inventoried a new `build.rs` that reads `../../shared/banner.txt` without
complaint; `linker_script_reference_must_be_an_inventoried_input` admitted a
repo-root `link.ld` named by `link-arg=-T../link.ld`. All three now refuse.

A final review round found that approving one entry file, or resolving a
linker reference against several bases, still left constructed holes. Each
was closed by forbidding the construct, red-first against `5d54bf40f`:
`checkout_build_script_module_change_refuses` (an approved `build.rs` whose
`mod helper;` changes), `decoy_package_linker_script_refuses` (a package-local
`link.ld` authorizing a reference the linker may resolve at the root) and
`response_file_pulling_external_linker_script_refuses` (an inventoried
`@link.rsp` naming an external script) all returned an Ok inventory and now
refuse.
