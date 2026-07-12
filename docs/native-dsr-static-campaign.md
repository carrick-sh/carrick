# Native DSR Static Campaign

This document records the Task 12 static-corpus campaign for the experimental
Darwin-native same-ISA dynamic syscall rewriter (DSR). It is a correctness
result, not a performance claim and not evidence that arbitrary AArch64 code is
supported.

## Result

At commit `6b10d3633ea5d8529e48d5e01e2186e990baf18c`, all 376 authoritative
static-musl AArch64 probes produced the same classified output and exit status
under native16k DSR as their cached native-arm64 Docker Linux oracles:

| Selected | PASS | DIFF | TIMEOUT | crash | typed deferral |
|---:|---:|---:|---:|---:|---:|
| 376 | 376 | 0 | 0 | 0 | 0 |

The final run completed in 109.00 seconds. The initial complete DSR run at the
start of this campaign passed 333 of 376 probes. No remaining row was placed in
the lane overlay: `scripts/conformance/baseline.native-dsr.jsonl` is
intentionally empty.

This result covers the checked-in static-musl probe corpus only. Dynamic glibc,
LTP, ecosystem workloads, generated code, and performance are Task 13 evidence
and are not inferred from this campaign.

## Reproduction

Build the runnable binary through the signed path, build the native PIE probes,
then run the probe gate from the repository root:

```bash
just build
scripts/build-probes.sh --native-pie
CARRICK_EXEC_BACKEND=native \
  CARRICK_NATIVE_PAGE_PROFILE=native16k \
  CARRICK_PROBE_LIBC=musl \
  cargo test -p carrick-cli --test conformance conformance_probes \
    -- --nocapture
```

The conformance harness also exposes the same execution mode as the isolated
`macos-native-dsr` lane. Its Carrick invocation injects:

```text
--exec-backend native --native-page-profile native16k
```

The lane retains the native `linux/arm64` Docker oracle and writes only
`baseline.native-dsr.jsonl`; it cannot bless the shared HVF baseline or support
matrix.

The lane is execution policy over the existing generated suite manifest, so
`scripts/conformance/suites.toml` does not need DSR-specific duplicate rows or
hand edits. Every existing arm64 suite remains selectable on this lane.

## Provenance

- Date: 2026-07-11 (America/Los_Angeles)
- Git: `6b10d3633ea5d8529e48d5e01e2186e990baf18c`
- Host: Apple M4, arm64
- OS: macOS 27.0, build 26A5378j; Darwin 27.0.0
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Decoder: `bad64` 0.12 series
- Emitter: `dynasmrt` 5.0 series
- Property tests: `proptest` 1.11 series
- Guest profile: Darwin-native `native16k`, DSR code mode
- Probe libc: musl
- Oracle: cached native-arm64 Docker Linux results; Carrick and Docker phases
  were not run concurrently

## Gap closure

Failures were reduced by execution mechanism rather than excused probe by
probe. Each mechanism was landed as a narrow commit with focused test and probe
evidence:

| Mechanism | Root cause and proof point | Commit |
|---|---|---|
| Shared host aliases | `MapHostAlias` outcomes were rejected, breaking shared file mappings, SysV SHM, shared futex aliases, high virtual addresses, and fork writeback. Targeted mapping tests plus all 24 affected probes passed after the fix. | `eee7efb2` |
| Thread-directed signals | `SignalThread` dispatcher outcomes were rejected. Targeted tests plus all nine initially affected probes passed after routing them through the existing native kicker. | `7257613b` |
| Signal deaths | `SignalDeath` was treated as unsupported instead of preserving Linux wait status. `seccompenforce` proved SIGSYS termination against its oracle. | `2b728fcf` |
| Asynchronous kicks | The gateway inherited the host's blocked kick signal and had an entry race while unmasking it. Red-first mask and entry-kick tests plus `itimer` and `sigchld` proved delivery. | `0eb15946` |
| Cross-thread progress | The DSR loop held `NativeMappedMemory` while translated guest code ran. LLDB showed one guest thread spinning while its sibling waited on that mutex. Splitting prepare, unlocked execution, and exit finalization made `altstacktid`, `mmapfileshare_mt`, and `telemetrymap` pass. | `4a79a0a5` |
| Invalid translated targets | Unmapped, NX, and unaligned indirect targets exited as backend failures instead of Linux guest faults. A red invalid-target test and all five `mprotectexec` invariants proved typed `SIGSEGV`/`SIGBUS` delivery. | `4281daf8` |
| Virtual-register branches | A linked conditional edge on virtual guest x18/x28 clobbered physical x17, so `vdsosymbols` lost its name offset after the first lookup. A red guarded linked-edge oracle and the original unmodified probe proved all four symbols. | `f35ebe04` |
| Exec and gateway lifetime | Exec cleared the old translator's PC metadata before kicked pre-exec siblings had retired, while kicks could interrupt the gateway's TLS and signal-mask transitions. Retiring translators now live through `Arc` ownership, and explicit entry/translated/host phases preserve completed typed exits. A 240-run no-cache stress campaign and the full corpus proved the lifecycle boundary. | `6b10d363` |
| Fast indirect edges | The one-entry indirect cache saved x17 after replacing it with the target and exposed partially mutated resolver state to kicks. It also relied on Darwin's custom physical x18 across the final branch. Production-guarded red-first oracles now cover x17, resolver recovery is contiguous for x15/x16/x17/x30/NZCV, and successful hits branch through ordinary physical x17 before restoring guest x17 at the target block. The enabled-cache build passed all 376 probes. | `6b10d363` |

The deterministic runtime DSR subset at the final static-campaign revision
passed 69 tests with two intentional ignores when serialized:

```bash
cargo test -p carrick-runtime --lib dsr_ -- \
  --nocapture --test-threads=1
```

The filter is serialized because these low-level tests manipulate process-wide
signal and fork state. That is a test-isolation constraint, not evidence for
parallel guest correctness; the static corpus contains the separate
thread/fork/signal proof points listed above.

## Stop-condition assessment

Task 12 stop condition 1 is met: all 376 authoritative native16k musl probes are
byte-identical with their Linux oracle classifications under DSR. Stop condition
2 is unused because there are no deferred static rows. Original guest text is
not patched in DSR mode, and no static probe reached an untyped fallback to the
original executable mapping.

This campaign did not make the native backend the default; HVF remains the
default backend. Darwin-native execution is now DSR-only, experimental,
same-ISA, native16k-only, and trusted-code-only. Task 13 records the dated LTP,
dynamic workload, generated-code, and performance evidence that informed that
later architecture decision.
