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

## Bundle and restore

Build requires the full current HEAD SHA and clean fixture source inputs. It
builds in a fresh `git archive` snapshot: an old executable or Cargo target
cache cannot stand in for a fresh output. Cargo locks, Cargo configuration,
fixture sources, probe inventory, build scripts, and compiler pin are hashed.
The source inventory conservatively includes all tracked workspace crates and
root Cargo manifests/lockfile: the EL1 scheduler fixture has local path
dependencies, whose source changes must also invalidate verification. Restore
does not need Cargo metadata resolution or registry access for this check.
Tracked source symlinks are hashed as their Git link declarations without
following them; executable objects and destination paths reject symlinks.
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
On a checkout at the same exact SHA:

```sh
just xtask fixtures restore --manifest /scratch/bundle/<manifest-sha256>/manifest.json
just xtask fixtures verify
just xtask fixtures verify --manifest /scratch/bundle/<manifest-sha256>/manifest.json
```

Restore verifies the address, commit, full source and executable inventories,
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
guest fixtures. Restore a new exact-SHA bundle after every checkout change.

## Contract and evidence

This is host-only acceptance/provisioning code outside guest execution. The
applicable invariant is exact source and executable identity for every signed
fixture, with work linear in input and executable bytes. No guest ABI, guest
scheduler, or guest-operation budget changes. The VM-free xtask tests cover
roundtrip installation, tampered/missing objects, manifest tamper, wrong SHA,
source drift, incomplete/duplicate inventory, wrong targets/toolchain,
permissions, symlinks, and missing/tampered installed files. The initial
red-first CLI test failed with `unrecognized subcommand 'fixtures'` on
`6a33e26b2` (see the implementation commit for the exact base SHA).

Signed execution and Docker differential acceptance remain director-owned.
The worker proof transfers a real ARM64 bundle to a cloudmac scratch checkout
and runs restore plus verification without starting guests or using the gate
worktree. Remote gate receipt: `director-queued`.
