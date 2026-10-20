Run on native ARM64 macOS, inside an existing supervised **gate** lease. This
runner does not acquire or upgrade leases. Use a fresh `CARRICK_RUN_ID` (safe
letters/digits/`_.-`, maximum 61 characters) exclusively for this run. Passwordless
`sudo -n scripts/sudo/kill.sh <run-id>` must work. Any cleanup that finds live
leftovers rejects the sample even if it successfully reaps them.

At the final clean HEAD, the director first runs `scripts/test-signed.sh
carrick-embed` with the required signed gates/negative control, and retains that
exact signed **release** `el1_sched` test executable. Do not enable
`conformance-metrics`. Restore and verify the source-matching signed fixture
bundle using the existing fixture workflow. Have a prebuilt `carrick-xtask`
available; the driver calls its `fixtures verify` command before measurement
(the verifier may use Cargo metadata, but never compiles guest fixtures).
Both Carrick and Docker must already have the same pinned ARM64 image available.
No builds, pulls, signing, or image changes are allowed during measurement.

For example, inside that gate scope (replace placeholders with actual paths and
the shared immutable image digest):

```sh
python3 scripts/perf/signal_delivery_contract.py \
  --binary target/release/deps/el1_sched-<hash> \
  --xtask target/release/carrick-xtask \
  --image registry/image@sha256:<64-lowercase-hex-digest> \
  --samples 20 --output target/signal-delivery-<unique-run-id>
```

The driver runs one explicitly excluded warmup pair, then at least 20 measured
independent pairs, always Carrick then Docker, with no concurrent guests. Each
invocation executes the unchanged `el1-sched wfi-signal 200` fixture. Carrick runs
only `el1_sched_signal_delivery_contract_sample`, which requires the explicit
`CARRICK_SIGNAL_CONTRACT_IMAGE` pin and real idle/WFI counts. Docker mounts the
same `target/embed-fixtures/el1-sched-aarch64` bytes. Guest p50 wake latency,
not cold-boot or test wall time, supplies the metric. The acceptance ratio is
median(Carrick per-invocation wake_p50_us) / median(Docker per-invocation
wake_p50_us), at most 2.0. Every pair contributes; none is retried or discarded.

`report.json` retains warmup, raw pairs, provenance and aggregate verdict.
Numbered `.stdout`, `.stderr`, `.json` files preserve every external command,
full output, timeout and exit status, including failed preflights/samples.
The first invalid sample aborts. Binary/fixture hashes, signature/CDHash,
LC_UUID, source HEAD/cleanliness, image identity and enclosing lease are checked
before/after samples. Final runtime evidence still requires director review and
the normal signed promotion gates. This measures parked-thread `tgkill`, handler,
`rt_sigreturn` and resumed futex wait; it does not prove every timer or signal
origin locking path. The contract descriptor and CI binding remain director-owned.

VM-free protocol tests:

```sh
python3 -m unittest discover -s scripts/perf -p test_signal_delivery_contract.py
```
