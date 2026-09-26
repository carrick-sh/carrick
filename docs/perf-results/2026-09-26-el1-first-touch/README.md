# EL1 anonymous first-touch: initial red witness

Source: `2c0b989c04bb1eb3c011268b9d01ad0ec5e14048`. The runtime is unchanged
from `d7393f616`; subsequent commits added the controller and test fixture.

Two live fork-related processes touch the same inherited, initially untouched
private anonymous mapping. Each verifies zero-fill, writes its own pattern,
and checks that pattern again after both have written. Pipe rendezvous and
whole-process alarms bound the fixture. All three scales pass those checks on
both native arm64 Docker and Carrick.

| Pages per process | Total pages | Carrick host exits |
|---:|---:|---:|
| 256 | 512 | 620 |
| 1,024 | 2,048 | 2,148 |
| 4,096 | 8,192 | 8,297 |

The first incremental slope is `(2148 - 620) / (2048 - 512) = 0.9948`
host exits/page. The second, derived from the raw counts, is
`(8297 - 2148) / (8192 - 2048) = 1.0008`. The signed test fails its first
`< 0.125` assertion after executing and checking all three scales. No budget
was widened and no failing sample retried. This establishes host work still
scales per page; it does not attribute every exit to a particular handler.

Command:

```sh
CARRICK_RUN_ID=el1-first-touch-red-20260926 \
CARRICK_CONTRACT_ID=kernel.el1.anonymous-first-touch RUSTC_WRAPPER= \
./scripts/test-signed.sh carrick-embed \
  el1_memory_first_touch_stays_in_guest --exact --nocapture
```

The harness returned 1, its unentitled negative control passed, and scoped
cleanup reported zero guests for both the run and CLI child IDs. It does not
publish a success receipt for failed runs. `artifact.txt` therefore attests
the candidate immediately after the run; the unchanged signed executable is
frozen at `target/el1-completion/first-touch/el1-sched-red-frozen`.

SHA-256: `e6782f7365676a6622b31b8d978b0a032fb43e4e61834cde91a07a668dc198d1`.
The artifact record includes CDHash, LC_UUID, entitlement and DOF. The only
untracked item at attestation was this evidence directory. The static fixture
hash is recorded before and after the signed build. No timing acceptance is
claimed from the printed diagnostic durations.

The Docker phase finished before Carrick started. Image ID, architecture and
repo digest are in `docker-image.txt`; the exact same static fixture ran at
all three scales. All raw stdout/stderr files and the signed harness log are
retained here.

## What remains

This is the initial first-touch witness, not full memory acceptance. The
in-guest implementation, exact fault/grant counters, denied-access checks,
publication rollback, foreign-memory coherence, elastic frame return, full
signed gates, and paired ecosystem measurements remain open.

Source inspection confirms a prerequisite: `PageTableManager` currently owns
host heap vectors and some readers (`foreign_mm/current_read.rs`) translate
through that software image. A guest leaf editor must not run beside an
unchanged authoritative host shadow. The next implementation work extracts
the existing page-table algorithm into a neutral `no_std` core and then makes
its live backing and mutation protocol usable by both venues. Core extraction
alone will not close this red witness or count as EL1 fault execution.

## Host authority and portability prerequisite evidence

`page-table-no-std-red.log` records the existing `carrick-mem` library failing
`cargo check --lib --target aarch64-unknown-none-softfloat` because its dependency
closure requires `std`. The unchanged page-table host baseline passed all 70
selected tests (`page-table-host-baseline.log`). These are extraction controls,
not guest-execution evidence.

`live-shadow-red.log` records a VM-free reproduction against the same runtime
base plus a test-only live-leaf mutation. After invalidating the hardware leaf
without editing the software image, a warmed current-MM read returned `Ok(())`
and copied `live`. The test also checks new preparation and unchanged output on
rejection. This is a migration prerequisite: EL1 leaf publication cannot safely
coexist with software-shadow read authority. It does not assert that an EL1
fault writer was already running in the tested product.

## Live snapshot red witness

`live-snapshot-red.log` is a second VM-free witness under
`kernel.fork.stage1-image`. A production carrier fixture first checks that the
host image sees its valid live page, invalidates that leaf only in the retained
hardware backing under the current-MM mutation authority, then takes the host
fork/rollback image. The image incorrectly translates the revoked address to
IPA `665719930880`; expected `None`. The test fails its semantic assertion,
not setup or compilation. Runtime implementation at this point is `cc270b3f0`
plus only the test/helper and contract changes. It does not claim guest fault
service is enabled. This red remains open until live storage and snapshots use
one authority; read-window correction alone did not solve it.
