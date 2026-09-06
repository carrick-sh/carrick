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

## Immutable lower view checkpoint

The VFS now carries immutable-lower provenance with host descriptors from its
cached dentry and immutable absolute-open paths. The memory trait passes that
provenance to HVF; immutable inodes use a host private view, while mutable
inodes retain the shared page-cache view. No writable descriptor is obtained
for the immutable cache. Guest page permissions and Carrick's first-write COW
remain in force.

Signed candidate SHA-256:
`47c2ef6cc8c92270f10c3179c950642e7bc66f0452608feabf994b68c7acb647`.
Python `print(1)` passed and all eight loader lowerings changed from error to
installed. The exact 100-mmap fixture recorded zero internal-copy bytes;
`CARRICK_MMAP_FILE_BACKED=0` on the same binary/fixture recorded 661,504,000
bytes and 161,500 copy chunks. Both selected exactly 100 mmap returns, with no
errors and scoped cleanup reporting zero remaining processes. The trace needs
the service-begin probe enabled before its argument companion will fire.

Receipts in the mmap worktree's `target/conformance/eco-mmap-resume/`:
`immutable-launch.log`, `lazy.{json,out,err}`, `eager.{json,out,err}`,
`mmap-copy-fixture.py`, and `run-mmap-check.py`. The successful run IDs are
`eco-mmap-immutable-lazy-1788712014738617000` and
`eco-mmap-immutable-eager-1788712049506751000`. Compile check, signed build,
and six serial runtime dentry tests passed.

This checkpoint is still NOT ready to land. Untraced five-trial medians for
mmap plus close were 551.981 us (whole libpython file), 610.702 us (6 MiB mutable
file), and 410.885 us (1 MiB anonymous). These fail the requested 10/6 us gate.
The resolved carrier samples identify repeated host arena resolution during
page-table synchronization and whole alias-registry cloning/diffing during
unmap as further amplification. Raw/resolved samples and LLDB image slides are
in `symbol-stacks2.log`, `resolved-stacks.json`, and `profile-images2.lldb.log`.
The full serial runtime suite and whole probe-family acceptance remain pending.


## Page-table publication amplification

The deterministic red-first test resolved one arena 1,122 times for one edit.
The missing-extension test also proved partial descriptor publication before
returning `UnresolvedArena`. `sync_to_host` now preflights each touched arena
once per publication, preserves the dirty journal on resolution failure, and
keeps descriptor order, atomic stores and barriers unchanged. The common case
uses stack storage; extension counts above eight also receive populated-prefix
notifications. No pointer survives this publication call.

Both tests failed before the fix (`pt-resolve-red.log`); all 190 carrick-mem
lib tests passed afterward (`pt-resolve-green.log`). These are host tests,
not the required signed page-table integration acceptance.


Signed `d7920a810` artifact SHA-256
`3841daa9542d26c96060d95c4f7abf159c8144b3da9bc2e871abb424e0b07610`
passed Ubuntu `sh -c /bin/true` and Python `print(1)` with scoped cleanup
(`pt-launch.json`). The unchanged five-trial benchmark measured 352.008 us
whole-file mmap+close and 276.501 us anonymous mmap+close, versus 551.981 and
410.885 us before arena preflight. This is a useful reduction, still a failed
10/6 us gate. Run `eco-mmap-immutable-bench-1788713258061447000`, receipt
`pt-bench.log`; earlier benchmark files are preserved as
`immutable-before-pt-bench.*`.


## Alias unregistration amplification

The full `unregister_alias` wrapper visited 2,052 rows when removing one alias
with 512 unrelated owners live (`unregister-red.log`). The bounded path
snapshots overlapping old keys and possible suffix keys, compares their
first effective rows, and invalidates only changed alias keys plus their old
and new physical replay owners. Replay epochs still advance on an alias-only
change even when replay rows themselves are unchanged. The remaining scope
bucket scan is not claimed constant-time.

The work-count test passes with a bound of 16 visited rows. Thirty split,
full-removal, duplicate-key, suffix-collision and no-op cases compare all alias,
replay and live version state against the old full-snapshot algorithm; overflow
also leaves state untouched. The signed full HVF library suite passed
437 tests with 3 ignored (`hvf-lib-signed.log`, run
`eco-mmap-hvf-lib-1788713559871706000`). Full runtime and probe acceptance,
latency gates and main landing are still pending.
