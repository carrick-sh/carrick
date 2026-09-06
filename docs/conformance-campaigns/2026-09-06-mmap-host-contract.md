# macOS private file mmap: host mapping contract

The parked mmap branch is not accepted. File/anonymous timing targets, zero
internal write bytes per whole-file mmap, full serial runtime tests, the mmap/COW
probe family, and the Ubuntu launch receipts remain required before landing.

## Proven copy-fallback cause

The `mmap-lowering-verdict` and `mmap-lowering-error` probes distinguish an
installed view from entry into its installer. On the rebased parked branch
(`0a589a2e9` plus diagnostic probes), the Python loader reaches the installer but
HVF returns `0xfae94001` at its stage-2 map. The dispatcher therefore takes its
byte-snapshot fallback. This code is `HV_ERROR`, not `HV_BAD_ARGUMENT` (the latter
is `0xfae94003`, verified in the installed Hypervisor.framework header).

A signed host-only reducer on the same macOS host maps the same regular file
through different descriptor access modes. It does not run guest code:

| Host mapping | Host descriptor | HVF R / RX / RWX |
| --- | --- | --- |
| shared file, PROT_READ | O_RDWR | all succeed |
| shared file, PROT_READ | O_RDONLY | all return HV_ERROR |
| private file or anonymous | O_RDWR | all tested protections succeed |
| file overlay inside anonymous extent | O_RDWR | succeeds |

Reducing stage-2 RWX to RX did not fix the runtime failure and was reverted.
Neither mixed host extents nor the selected stage-2 permission explains this
failure. The next fix must respect the host mapping authority while preserving
guest read-only descriptors and Linux private clean-page/COW semantics.
Immutable lower file authority must not be made writable as a shortcut.

Director reducer source and transcripts are under main checkout
`target/conformance/eco-final-ledger/hvf-file-map-contract.c` and
`hvf-file-map-{contract,mixed,rofd}.log`. Runs were stamped respectively
`eco-hvf-map-contract-20260906`, `eco-hvf-map-mixed-20260906`, and
`eco-hvf-map-rofd-20260906`; each returned zero after destroying its HVF VM.
These are mapping-contract results, not timing receipts.

## Diagnostic change validation

The outcome probe uses a typed enum. Error messages are formatted only inside
the enabled USDT closure. `scripts/dtrace/trace_lowering_verdict.d` names the
four-argument ABI, rejects DTrace errors, labels an empty capture unusable, and
bounds collection at 25 seconds. Per-event diagnostic printing perturbs failing
mappings; no latency result from this script is accepted.

`cargo check -p carrick-runtime`, signed `just build -p carrick-cli`, and the
live Python `print(1)` diagnostic capture passed. The capture remains RED for
lowering: actual error events confirm the unresolved fallback. Logs are in the
mmap worktree's `target/conformance/eco-mmap-resume/director-instrumentation-*`
and `director-diagnostic-receipt.log`. This is an instrumentation checkpoint,
not a runtime-fix or branch-landing receipt.
