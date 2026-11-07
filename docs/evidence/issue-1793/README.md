# KVM ecosystem attempts at the admitted main

This is the original attempt report. See the [followup diagnosis and direct
eight-row table](followup.md) for the subsequent investigation.

The eight requested commands were attempted, but **the ecosystem scoreboard is
not measured**. No command produced its expected output. Five launches exited
127 without a diagnostic; three reached the 120-second SIGKILL deadline. These
are not eight language-runtime failures, and they do not answer whether the
ARM blockers are shared with x86.

The clone has usable real KVM: `kvm-access.log` records API 12 and successful
`KVM_CREATE_VM` as the dispatch user under the inherited VM-local gate lease.
All three public `linux/amd64` images pulled successfully. Their manifests,
configs (including architecture and PATH), and full digests are in `images/`.
Docker is unavailable on this host; HVF is unavailable on Linux.

## Results

“None” below means both saved output streams are empty; no first error line
exists to quote. A deadline status is 137 from SIGKILL, not guest exit 137.

| Workload | Result | Observed exit | Full first error line | Comparison with ARM |
|---|---|---:|---|---|
| Go `go version` | Not measured: silent launch failure | 127 | None | ARM passes; no Go version or fatal observed here |
| Go `go run hello.go` | Not measured: silent launch failure | 127 | None | No `entry_binding`, reason, or `at=` to match #887 |
| CPython start | Not measured: startup deadline | 137 | None | ARM passes; no Python version observed here |
| CPython thread | Not measured: startup deadline | 137 | None | ARM passes; host snapshot shows prelaunch file copy |
| CPython `os.fork()` | Not measured: silent launch failure | 127 | None | No `child-ok`/`parent-ok`, SIGSEGV, or #1733 error |
| CPython `subprocess.run` | Not measured: silent launch failure | 127 | None | No `sub-ok`, SIGSEGV, or #1733 error |
| Node `process.version` | Not measured: image-setup deadline | 137 | None | No V8 CodeRange refusal or #1791 error |
| Node `child_process.execSync` | Not measured: silent launch failure | 127 | None | No V8 CodeRange refusal or #1791 error |

These are **different observations**, not proof of a different root cause or an
ISA-specific defect. The failures on ARM may be hidden behind an earlier launch
block here. `arm-baseline.md` retains the exact main scoreboard and its source
comment. ARM used conformance images; this task deliberately uses the requested
public images, so this also changes image contents.

## Evidence and interpretation

`run-1/rows.tsv` records the first seven rows with run IDs; `run-2/rows.tsv`
records only the previously unexecuted Node child row. Each has its exact
`.command`, `.out`, `.err`, and scoped `.cleanup` file. The harness records
statuses as “executed” to mean the **CLI was invoked**, not that guest execution
was proven. The table above is the interpretation of those raw observations.

At the recorded instants, `run-1/py-thread-prelaunch-snapshot.txt`,
`run-1/py-subprocess-host-snapshot.txt`,
`run-1/node-version-host-snapshot.txt`, and
`run-2/node-child-host-snapshot.txt` show host-side layer extraction/copying,
blocked host I/O, and no open KVM descriptor. They do not establish where every
other attempt ended. In particular, a silent 127 is ambiguous: Carrick's
`classify_run_outcome` in `crates/carrick-runtime/src/prepare.rs` maps missing
entrypoint/interpreter errors to an empty result with exit 127.

`diagnose.sh` performs separate bounded shell-marker and explicit-loader
launch diagnostics with `--json`; their outputs live in `diagnostics/`. They
are not substitutes for any scoreboard row.

The shell marker timed out (137), with a contemporaneous snapshot again
showing image copying and no KVM descriptor. The explicit-loader diagnostic
returned 127. Its JSON does prove actual `kvm-x86-cpl0` execution: 9 guest
entries, 6 traps, and 4 syscall invocations, with empty guest stdout/stderr.
Thus real KVM works beyond the host preflight, but even this diagnostic did
not print its shell marker. Its exit is a different observation from the ARM
fatal signatures; its underlying cause remains unidentified. It cannot confer
an ecosystem result on any earlier row.

## Artifact and reproduction

The release binary was built while HEAD was exactly
`71c57e106688ba954a5a9947c9868f8a92160660`, using:

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux --release
```

`build.log` records success with optimized code and debuginfo. Its SHA-256 is
`50184689cf7f3cae5da2ee6120e38ec12f539ed07cb881cf79ae8e0dfb33589d`.
`run-1/identity.txt` records that HEAD and digest. The later evidence-only commit
changed the recorded HEAD for `run-2`; the binary was not rebuilt and its digest
remained identical. No Carrick source was changed.
`artifact-check.log` confirms the digest and that the second pulls retained
the original image manifests.

The runner used the installed pinned Rust 1.96.0 toolchain from
`/opt/carrick-rust/rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin`, prepended
to PATH. Every build, preflight and workload reused the job's VM-local gate
lease via `just lease gate`; no hypervisor lease was acquired.

From the repository root, with the Linux release artifact present:

```sh
CARRICK_REQUIRE_KVM=1 just lease gate bash docs/evidence/issue-1793/run.sh /absolute/new-output
CARRICK_REQUIRE_KVM=1 just lease gate bash docs/evidence/issue-1793/diagnose.sh /absolute/new-diagnostics
```

The known-answer runs prove both streams are captured, exit 7 survives, and a
five-second sleeper is killed after one second. Runtime waits remain bounded
to 120 seconds; no deadline was raised and no workload was retried until green.

## Harness correction and cleanup limits

The first seven rows used `run.sh` as committed in `40f16257c`. During that run,
the author edited the script to use `timeout --foreground`. Bash's live reader
then lost its byte position before the eighth row. The full first harness error
is retained in `harness.log`:

```text
docs/evidence/issue-1793/run.sh: line 73: ode:24: command not found
```

This is a harness error, not a Carrick error. Only the missing eighth workload
was launched with `ONLY_ROW=node-child` in `run-2`; none of the first seven
workloads was repeated. Future runs use `--foreground`, verified by
`foreground-known-answer.log`, so timeout survives to wait for its child.

Every scoped reaper reported zero remaining matching processes. However, the
initial group-wide SIGKILL also killed timeout itself: its dead children lost
their run-ID proctitle and could remain zombies owned by the job supervisor.
Thus those zero counts prove no live matching carrier remained, not complete
OS-level reaping. This limitation means the initial run does not satisfy the
acceptance's full reaping requirement. The foreground runner corrects future
runs without concealing the original evidence.

## Verification

- Requested Linux release build: passed (`build.log`).
- Real KVM API/VM preflight: passed; explicit-loader diagnostic additionally
  records actual CPL0 guest entries.
- Both runner syntax checks and host known-answer checks: passed.
- `just check-contract-change 71c57e106688ba954a5a9947c9868f8a92160660 HEAD`:
  passed; changed files are evidence only.
- `just xtask authority-debt --source-only`: passed using the checkout-built
  xtask (`authority-debt-current.log`, 1266 counters). The earlier preinstalled
  xtask attempt failed with ENOENT (`authority-debt.log`); its failure is kept.
- Required pre-push hook (`sh .githooks/pre-push`, invoking `just clippy`):
  passed (`clippy.log`).
- `just fmt-check`: passed. The full staged diff check reports trailing
  whitespace in the two diagnostic `.command` records and one raw `ps` line
  in `py-fork-host-snapshot.txt`; these records are retained as captured.

No Rust crate was touched, so no crate-specific regular/`serial_host` suite,
macOS cross-check, Linux HAL cross-check, or CPL0 rebuild gate applies to a
source change. The requested CLI build did build its KVM/CPL0 dependencies.
The whole KVM test gate, whole-workspace lint/kernel gates and signed HVF gates
were not run. Docker is not installed; HVF requires macOS. This evidence does
not claim any of those gates passed, nor any NEW/FIXED conformance verdict.

The remaining blockers are launch completion within the required bound, silent
127 diagnosis, and the original timeout method's unreaped dead children. They
must be resolved before this issue can have an ARM-vs-x86 ecosystem scoreboard.
