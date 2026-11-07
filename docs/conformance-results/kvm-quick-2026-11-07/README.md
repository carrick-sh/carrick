# KVM quick-tier measurement attempt

Part of #1795. **Not measured:** this attempt does not establish x86
conformance or complete step 3. No Linux semantics or runtime source changed.

The quick tier is called `smoke` by `carrick-conformance`. Its complete
selection is 23 suites: ten LTP, five Go, two Node and six CPython suites.
The runner explicitly selects all four ecosystems, since an unfiltered
`kvm-local` invocation otherwise excludes CPython.

## Oracle and image admission

The committed cache has current `linux/amd64` keys for 15 selected suites:
all ten LTP and all five Go suites. Both Node keys are missing. The six
CPython suites have historical amd64 records, but they lack the current
`regrtest-v4-deferred-status` parser fingerprint and are not usable answers.
`cache-audit.json` records each suite and its ARM baseline verdict; all 23
are `match` in the admitted ARM baseline. Those historical ARM results do
not prove current x86 behavior.

All four declared images are private `localhost:5005`/`localhost:5050`
fixtures. Neither registry is serving this clone. Public stock Go, Python
or Node images are not interchangeable with these baked test images: changing
the image declaration changes the oracle key, and the baked test commands
and entrypoints are not generally present in stock images. No public-image
alias was substituted into a cached private-image answer.

This native x86_64 Linux runner can open `/dev/kvm` (API version 12), and
inherits the dispatch job's VM-local gate lease. It has neither a Docker
executable nor a Docker socket, so targeted missing oracle rows cannot be
filled here. No Docker oracle pass was attempted.

## Results

MATCH, DIFF, Carrick-only failures and oracle-only failures are all **not
measured**, rather than zero. A cache-admission failure is not a guest
failure or a passing test. No new x86 verdict is eligible for
`scripts/conformance/baseline.kvm.jsonl`.

The actual harness exited 2, naming exactly the eight cache misses above
(`quick.log`, `quick.exit`). Its dry run planned 23 Carrick commands and 23
Docker commands, all with `--platform linux/amd64` (`plan.log`); the Docker
commands were printed only. No `results.jsonl` was created and no workload
started in this all-suite invocation. This is a known-answer check of cache
refusal, not a known-answer check of successful guest execution. Both release
builds passed; this build did not encounter the missing fixture-lockfile
blocker described in #1794. `inputs.sha256` identifies the tested artifacts.

| DIFF suite | First differing line | Also fails on ARM? |
|---|---|---|
| Not measured | No differential workload result | Not established |

One cached row was also attempted separately to test what could run:
`ltp-gettid01` (`gettid.log`, `gettid.jsonl`, `gettid.exit`, `raw/`). The
harness admitted its amd64 oracle (2/2 assertions), ran zero Docker commands,
then exited 1 with `INCOMPLETE`: Carrick could not resolve the private LTP
image. The local image store was empty (`images.log`). The first diagnostic
is `carrick: failed to resolve image: OCI registry operation failed` in the
raw stderr. No guest assertions ran, and the missing syscall census follows
from that startup failure. This is one infrastructure failure, not a measured
Carrick-only semantic failure. Its ARM baseline is `match`; shared versus
x86-only guest attribution remains unestablished.

The cached embed probe shards cannot replace this missing measurement:
`carrick-conformance-next/tests/probes_shard_{1,2,3}.rs` explicitly select
AArch64 GNU/musl binaries and ARM oracle directories. No x86 generic-shard
execution is claimed.

## Reproduce

From the repository root, with the pinned Rust toolchain and `just` on PATH:

```sh
scripts/conformance/measure-kvm-quick.sh /absolute/new/evidence-directory
```

The script builds the Linux release CLI and harness under `just lease gate`,
records input hashes and the dry-run plan, then runs with
`CARRICK_REQUIRE_KVM=1`, `--require-cached-oracle`, `--no-image-refresh`, no
flake retries and exhaustive selection. Missing keys fail before execution;
the script never refreshes or fills an oracle. It captures exit status and
both raw streams when workload commands actually start. The output directory
must be new so prior evidence cannot be mistaken for this run.

To unblock the measurement, supply reachable amd64 baked fixtures with
authenticated oracle identities, and fill only specifically missing or
doubted rows on a native x86 host with Docker. Public fixture declarations
need their own committed answers. Run Docker and Carrick in separate phases.
Do not rewrite keys or use an ARM answer as an amd64 answer.

No defect issues or GitHub comments were filed: this dispatch explicitly
reserves publication for the server, and no guest defect was measured.

## Verification

The initial clean Linux release CLI build, the runner's locked release CLI
and harness builds, script syntax check, `just fmt-check`, the Linux
`just clippy` pre-push gate and `just xtask authority-debt --source-only`
passed. The cache-refusal known-answer check confirmed 23 planned amd64
commands, eight named misses, exit 2 and no all-suite result file.
The targeted fixture-admission attempt failed as recorded above.

No crate source changed, so focused crate suites, `just check-linux`,
`cargo check -p carrick-vmm-kvm` and `just cross-check-macos` are not required
for this slice. Full KVM acceptance and ecosystem guest measurements were
not run. HVF is unavailable on Linux. Whole-workspace `just lint-domains`
and `just test-kernel` are left to CI as instructed. The contract-change
check is also run against the final committed head before handoff.
