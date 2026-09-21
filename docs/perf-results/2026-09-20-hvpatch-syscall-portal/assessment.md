# Adaptive syscall portal assessment

## Decision

The executor-local helper portal is rejected as the next `inotify09`
optimization. It remains useful design evidence, but its production integration
was reverted by `a5bb139b4` after the signed A/B showed both worse steady-state
cost and an unsafe cancellation race. Portal policy was never enabled by
default.

Carrick's acceptance target remains unchanged: Linux semantics plus no more
than 2.0 times native-arm64 Docker on the same workload.

## Artifact

- source revision: `e71105fef`
- binary SHA-256: `f96cd3f9db8f214cea65a7c05936b1b38a8c073bec1e894720bd37e34306f9c1`
- CDHash: `d2b379be9c8aa5c9886b3c3822793a14da647eec`
- LC_UUID: `B91802AF-CC14-3268-9BCC-820853EB948F`
- entitlement: `com.apple.security.hypervisor = true`
- USDT section: `__DATA,__dof_carrick` present
- probe: `perf_inotify09_scale`, clean-room `Apache-2.0 OR MIT`, SHA-256
  `6c2d5cbcaefa380345c6794b5953a416107b81e2457a10fc389530e80e165ba8`
- image: `localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`

Carrick and Docker ran serially. Scoped run identities were
`portal-decomp-off` and `portal-decomp-adaptive`; no Carrick process remained
after the adaptive failure.

These are diagnostic rejection measurements, not acceptance receipts. The
commands used the local image tag (the digest above was inspected), and the
probe executable was hashed but not freshly rebuilt and source-attested for
this comparison. Process CPU and deterministic work counters were not captured.
The results justify rejecting this implementation; they do not qualify the
remaining implementation or close any promotion gate.

## Scale 65,536 result

Nanoseconds per iteration are p50 over 21 samples.

| Phase | Carrick portal off | Docker | Off / Docker |
| --- | ---: | ---: | ---: |
| watch churn | 4,459 | 969 | 4.60x |
| write + seek | 5,699 | 458 | 12.44x |
| persistent-watch write + seek | 5,734 | 566 | 10.13x |
| serial full body | 12,876 | 1,546 | 8.33x |
| concurrent components | 8,665 | 1,139 | 7.61x |

The portal-off arm completed every phase. The adaptive arm did not reach the
65,536 point. At scale 8,192 its completed phases were already slower than the
same artifact with the portal off:

| Phase | Portal off | Adaptive | Adaptive / off |
| --- | ---: | ---: | ---: |
| watch churn | 4,450 | 9,589 | 2.15x |
| write + seek | 5,622 | 11,268 | 2.00x |
| persistent-watch write + seek | 5,681 | 11,501 | 2.02x |
| serial full body | 12,943 | 15,939 | 1.23x |

The adaptive run then failed at mailbox sequence 77,140. EL1 reached HVC with
state `Disabled` and no ordinary request publication. The helper's activity
expiry had raced the guest's non-atomic `Armed -> RequestReady` transition.
Both sides can overwrite the shared state because EL1 uses a load followed by
an unconditional release store. State checks, a longer timeout, or a different
denylist cannot make that ownership transfer atomic.

The exact signed LTP run also remained red: `conf-67654-s00` reached the 40 s
declared budget versus the cached 10.344 s Docker result, a 3.89x lower bound.

## Consequence

The next performance work targets the same-vCPU owner path. The decomposition
names regular-file `write + lseek` as the largest measured phase gap. A useful
replacement must remove an HVC without a cross-core request/response handoff.
The next candidate to evaluate is Carrick-owned open-file-description offset
authority with positional host I/O and a typed, generation-authenticated EL1
capability for the narrow regular-file seek operation. It must cover dup/fork
sharing, concurrent access, append, sparse files, signals, and stale capability
rejection before production admission.

## Post-revert verification

The production source at `a5bb139b4` was rebuilt with `RUSTC_WRAPPER= just
build`; only the assessment documentation changed in `e2c6353fd` during that
build. All 24 VM-free `carrick-kernel-example` contract tests passed.

- binary SHA-256: `7177143f6341f9784631d269ecf05f3eaa4ea44e48650f1f984350797c188e27`
- CDHash: `1c4825fc9064a92bcbd39fa75673fb49795ef962`
- LC_UUID: `D90ED10E-2976-39E9-9400-316A5E04F133`
- hypervisor entitlement and `__DATA,__dof_carrick`: present
- ledger: `target/conformance/portal-revert-inotify09.jsonl`
- declared-budget run: `conf-74312-s00`, timeout at 40.316 s

Both raw streams were inspected. The stderr transcript reported progress to
35,890 loops, with thread A's body averaging 3,939 ns and thread B's 9,545 ns.
Those are LTP's internal sampling observations, not an uninstrumented complete
runtime or proof of deadlock. The harness classified the timeout `[blocked]`,
but the transcript establishes ongoing progress during the run. The oracle
was cached; no new Docker acceptance run was performed. Binary SHA-256 was
unchanged afterward, and a process inventory found no remaining Carrick guest.

The signed probe, smoke, and full promotion gates remain open. The next
attribution must include the fuzzy-sync waiting/clock cost as well as the
write/seek body before selecting a replacement architecture.

## Post-revert live syscall attribution

On the same signed binary, `inotify-census-revert` ran the digest-pinned LTP
image with `/bin/sh -c /opt/ltp/testcases/bin/inotify09`, `--fs host`, and
`--max-traps 0`. The bounded ten-second service census completed with zero
DTrace errors and a successful required-exit receipt. Counts were 409,310
watch additions, 409,310 removals, 409,309 seeks, 409,333 writes, and just one
host-serviced clock call. This supports the EL1 raw-clock path being active
in the real workload; repeating clock fast-path implementation is not the
next action. See `inotify-census-revert.trace`. Instrumented timing is not
performance acceptance evidence.

The subsequent `inotify-hotpath-revert` capture was correctly rejected by
`--require-script-exit`: its service join reported `mismatch=1`, `complete=0`.
Its aggregate host-call ratios and durations are not admissible attribution.
The raw rejected capture is preserved in `inotify-hotpath-rejected.trace` to
diagnose the instrument before relying on its joins. Both bounded runs left
no live Carrick guests. Next: repair/replace that join or use independent
host-call counts before deciding whether host metadata work or exit overhead
is the next production target.

An independent whole-tree Darwin census (`inotify-host-census.trace`) then
passed the required-exit check, with zero errors at its ten-second bound.
It recorded 373,257 host seeks, 373,323 writes, 746,614 `fstat64` calls and
746,900 `fstatat64` calls. Startup is included, so these are approximate
per-cycle counts, not a service-window join: about two of each metadata query
per write/seek cycle. This establishes metadata amplification as a concrete
candidate before a new offset-authority architecture. The current write path
calls `invalidate_dentry_host_fd` after each positive write, which resolves
the stable inode identity with a fresh `fstat`. Any optimization must retain
invalidation after every mutation, including after a cache refill and across
descriptor aliases; the prior idea of invalidating only once per open cannot
establish that invariant.

## Descriptor identity candidate

The next candidate caches only immutable device/inode identity on `HostFdOwner`
and reuses it for positive regular-file write invalidation. Cache invalidation
still occurs on every positive write, and failed identity queries are retryable.
Aliases share the owned descriptor and identity; closing it retires both.

The cache-refill regression failed with invalidation deliberately disabled
(cached size 64, expected 128), then passed after restoring invalidation.
A separate test passed for unlink/path replacement and surviving descriptor
aliases. The signed census passed with 369,966 host seeks, 370,033 writes,
370,074 `fstat64` and 740,318 `fstatat64`: one repeated `fstat` per write was
removed, while path metadata work remains. This is a structural improvement,
not an end-to-end timing or promotion claim. No guest remained after capture.

Candidate artifact, based on `5bde8b924` plus the descriptor-identity diff:

- SHA-256: `4a704873cf7643acabbaf4c24f1750cb7c4360a47f66fde1a7499fffc818bdd9`
- CDHash: `778cf9d92a3944cca39ffb4440a229bb868f4145`
- LC_UUID: `246D6BA2-EB1C-3DDF-813D-DF7DDA5525C1`
- hypervisor entitlement and `__dof_carrick`: present
- raw capture: `inotify-inode-cache.trace`

Contract surfaces remain `kernel.fs.write-seek` and the inotify09 hot path.
Signed embed/probe, smoke/full promotion and <=2x timing acceptance remain open.

The unchanged candidate artifact subsequently failed the declared 40-second
`ltp-inotify09` budget (`conf-78564-s00`, 40.242 s), recorded in
`target/conformance/inode-cache-inotify09.jsonl`. Both raw streams were read;
the last LTP sampling report showed 1,860 loops and thread B at 8,419 ns.
That report is not a completion count and does not prove a runtime speedup.
The Docker row was cached, the binary hash remained unchanged, and no Carrick
guest remained afterward. The removed metadata syscall is a measured work
reduction, but the workload remains red.

Source attribution for the next candidate: private-rootfs watch creation calls
`path_exists -> inotify_path_kind -> RootFsVfs::lookup -> dentry_stat`, which
refreshes mutable inode metadata after a write invalidates it. The existing
`DentryCache::lookup_path` can resolve existence/kind without that refresh.
Before substituting it, cover symlink following, missing paths, unlink/recreate,
and directory-kind behavior; retain full metadata refresh for actual stat calls.

## Namespace-only watch lookup candidate

`RootFsVfs::dentry_is_dir` uses the existing symlink-following namespace
resolver without refreshing inode attributes. Inotify's rootfs kind query uses
that answer when available and preserves its prior lookup fallback otherwise.
The regression failed against the full-stat implementation because it refilled
invalidated inode metadata, then passed with namespace-only lookup. It also
checks a followed symlink, root directory, missing path, dangling symlink after
unlink, and a replacement directory. All 24 VM-free contracts and five inotify
semantic tests passed.

The required-exit census passed with zero errors: 425,986 host seeks, 426,052
writes, 426,093 `fstat64`, and just 398 `fstatat64` calls including startup.
Thus the two per-loop path metadata queries disappeared. Instrumented
throughput is not a timing acceptance claim. Raw: `inotify-kind-cache.trace`.

Artifact based on `489cd1fb9` plus the namespace-only lookup diff:

- SHA-256: `166143994b2502b38687b63deda3106da1e1d720e2c8d21d4faf576ae35f6086`
- CDHash: `c6c7b7a034ae925f054dba8d8d08f93780b04342`
- LC_UUID: `09BD6C70-38FB-3B17-88C6-B77DE04BFE4E`
- built through `just build`; `__dof_carrick` present

Signed promotion and <=2x end-to-end acceptance remain open.

The same artifact still timed out at 40.275 s in the uninstrumented declared
budget run `conf-79640-s00` (`target/conformance/kind-cache-inotify09.jsonl`).
Both streams were inspected; the final emitted sampling report named loop
10,413, A=3,799 ns and B=8,876 ns. The oracle was cached. SHA-256 was unchanged,
the hypervisor entitlement was verified, and no guest remained. Reduced
metadata work has therefore not yet established a complete-workload runtime
gain; the next attribution must explain the sustained workload cost.

## Sustained carrier CPU ranking

On the same namespace-only artifact, the built-in
`hvpatch-carrier-cpu-low-rate` profile sampled the real LTP workload under a
guest `timeout 30s` diagnostic wrapper. This deliberately does not supply an
LTP verdict or runtime acceptance. The corrected invocation returned zero and
validated 5,813 samples, 939 distinct stacks, exact population closure, zero
errors, root exit and no profile deadline expiry. Scoped cleanup was empty.
An initial invocation incorrectly requested unsupported `--summary-jsonl`;
it was not accepted, and the corrected capture replaced it as evidence.

Symbolication used the live image-base receipt `0x100970000` and the exact
signed artifact. 3,951/5,813 samples (68.0%) contain `applevisor::Vcpu::run`:
this is an opaque guest/HVF/trampoline bucket, not measured host-dispatch CPU.
The first Carrick frame was `write_host_file` in 319 samples (5.5%). Other
smaller groups included time reads, HVF register access, dispatcher and executor
work. This does not support attributing the whole remaining gap to metadata.
Separating guest spin from transition cost is the next performance question;
the guest spin may itself depend on service latency, so the 68% is not an
independent Amdahl bound.

Retained local artifacts:

- `target/perf/inotify-sustained/carrier.trace` (complete validated raw capture)
- `target/perf/inotify-sustained/symbols.json` (offline symbols and ranking)

The guest timeout produced the expected interrupted LTP diagnostic, including
TBROK; profile success certifies only the complete CPU sample population.

### Harness configuration correction and fresh oracle

The harness dry-run showed `--max-traps 18446744073709551615`, whereas the
diagnostic captures above used `--max-traps 0`. Zero is not the harness's
disabled limit and can introduce watchdog clock reads. The metadata census
observations remain counts of those diagnostic configurations; do not use
their throughput or the earlier CPU ranking as exact harness measurements.

The CPU profile was repeated with the harness's exact trap limit. It returned
zero with 5,813 samples, 963 stacks and exact closure. Using its live image
base `0x100e00000`, 4,019 samples (69.1%) contain `Vcpu::run`; `write_host_file`
is the first Carrick frame in 316 samples (5.4%). This supersedes the earlier
ranking without changing the broad finding. No Carrick guests remained.
Raw and symbolized results are `target/perf/inotify-sustained/harness-carrier.trace`
and `harness-symbols.json`.

Before that Carrick phase, a fresh native `linux/arm64` Docker run of the same
digest-pinned image and `/bin/sh -c /opt/ltp/testcases/bin/inotify09` passed
1/1 with zero broken/skipped cases in 5.75 s wall time, measured around
`docker run --rm` (including container startup). This is faster than the cached
10.344 s baseline, so the remaining gap is not explained by a slow current
oracle. An initial attempt to use `time` inside the image failed before LTP
because that command is absent; the reported run used host `/usr/bin/time`.
This diagnostic did not rewrite the committed oracle cache.

## Component timing: EL1 versus ordinary host dispatch

Extended the existing `perf_trap_floor` probe with raw `CLOCK_MONOTONIC` and
invalid-fd `lseek`, retaining its existing identity/control output keys. Clock
success and rejected seek/EBADF are checked outside the reported results.
The stale documentation claiming identity calls necessarily reach the host was
corrected. Both runs used the same freshly built ARM64-musl executable and
digest-pinned LTP image, serial Carrick then native Docker, with the harness
trap-limit setting on Carrick.

Final formatted probe source SHA-256:
`869a08952e9758fb9fdde17080a450d3c3887ce150928fd294bf2823be61f51e`;
executable SHA-256:
`d0f0357a2d1272de1cc021d25cab28df239d6f6c18a41eb5a255b80ee6433df8`.
The Carrick artifact is the namespace-only artifact above. Earlier pre-format
probe measurements are superseded by this final artifact's receipts.

| Batched p50, microseconds | Carrick | Docker |
| --- | ---: | ---: |
| raw getpid | 0.026 | 0.135 |
| raw gettid | 0.026 | 0.120 |
| raw monotonic clock | 0.086 | 0.138 |
| invalid-fd lseek | 1.573 | 0.125 |
| empty control | 0.000 | 0.000 |

The ordinary host-dispatch case is 12.58x Docker, whereas these EL1 paths are
already faster. This changes the next target to ordinary syscall dispatch and
VM entry/exit overhead, not clock transport. The invalid seek is a lower-work
dispatch case, not a claim about every syscall or full inotify runtime. Zero
rounded control values are below reporting resolution, not literally free.
Raw receipts: `target/perf/inotify-sustained/trap-components-carrick.txt` and
`trap-components-docker.txt`. No acceptance budget is changed or closed.

### Isolated host dispatch and mailbox measurement correction

The probe now accepts `host-dispatch`, performing 10,000,000 invalid-fd seeks
without LTP synchronization or clock calls. The isolated CPU capture completed
with zero unexpected results and exact closure of 1,786 samples / 642 stacks.
782 samples (43.8%) include `Vcpu::run`; register reads also appear through
the legacy decode closure in `MailboxBinding::decode_request`. This isolates
transport cost from LTP spinning, but the opaque VCPU frame still cannot be
attributed wholly to host overhead.

Probe source SHA-256:
`320b6ab63297e078bfdd993699d541fa8224b2af6aaaf3476659fdeadff19c29`;
executable SHA-256:
`e27f0f1e37f62db6b8a10ed2e2f62d6b2ee4ad3ab615431ab4fc3323a3d4498d`.
The signed Carrick artifact remains unchanged. Local receipts are
`target/perf/inotify-sustained/isolated-carrier.trace` and
`isolated-symbols.json` (live image base `0x10067c000`).

An explicit mailbox component run reported invalid-seek p50 1.411 us and raw
clock 0.083 us (`trap-components-mailbox.txt`). This is a diagnostic observation,
not a fresh ABBA campaign or promotion result. Mailbox `inotify09` run
`conf-81801-s00` timed out at 40.215 s; a host debug build overlapped its tail,
so it is not clean timing evidence. Both raw streams were inspected and process
cleanup verified. No parity is claimed.

The historical mailbox campaign selected `trap_batch_trimmed_mean_us`, which
times EL1 identity calls. Its transport metric now selects
`invalid_seek_batch_trimmed_mean_us`. The regression test failed with the old
selection and passed after correction. Missing new metrics fail parsing rather
than falling back to the old identity metric. The historical report is annotated;
its raw evidence and promotion thresholds are unchanged. Fresh qualification
must also use the current HVPatch execution lane rather than assume the retired
VMM campaign invocation remains applicable. No runtime default changes here.

### Balanced HVPatch boundary comparison

At source `5acff4f74`, explicit `run-elf --raw --exec-backend hvpatch` completed
10 warmup ABBA blocks followed by 30 measurement blocks, 60 samples per mode,
with four exposed CPUs. Each leg ran serially on the same signed binary and
static-musl probe identified above; both hashes were verified unchanged after
sampling. All 160 invocations returned zero and reported `nproc=4`; no guest
processes remained after the campaign.

Median `invalid_seek_batch_trimmed_mean_us` was 1.7105 us legacy and 1.537 us
mailbox. The mailbox/legacy ratio was 0.89857, with a percentile bootstrap 95%
interval [0.89586, 0.90170] (10,000 resamples, seed 5634344305327363654).
This clears the existing boundary estimate <=0.90 / upper <1.00 threshold.
It does not qualify end-to-end guards, Linux parity, or signed promotion.
The diagnostic uses the current static-musl ELF rather than the historical
native-PIE build; it is a fresh HVPatch comparison, not the old full campaign.
Every invocation and raw output is retained in `mailbox-hvpatch-abba.jsonl`.

The reusable transport campaign command was separately corrected from retired
`vmm` to explicit `hvpatch`, with an argv regression test red on `vmm` and
green on `hvpatch`. Historical native-versus-VMM comparators remain untouched.
The full transport campaign still requires freshly built probe artifacts and
all end-to-end rows before a default change can be considered.

### Full current HVPatch transport campaign: promotion rejected

`hvpatch-mailbox-full.jsonl` records the eight-workload campaign at
`2f56d817b4e52823ed1813f4947d583bdfda8e7c`: ten warmup and thirty measured
ABBA blocks per workload, sixty samples per mode, zero cooldown as in the
historical campaign. All eight static-PIE probes were freshly built with the
repository's `rust:alpine` / `cc -static-pie` recipe. A local rust-lld build
attempt rejected the compiler-driver `-static-pie` flag before any execution;
none of those failed outputs were measured. The report includes each executable
hash and validates unchanged probe and Carrick hashes after measurement.
Dirty source status reflects the three unrelated untracked plan files.

| Workload | Mailbox / legacy | 95% interval | Frozen verdict |
| --- | ---: | --- | --- |
| host-dispatch floor | 0.8974 | 0.8925–0.9016 | Pass |
| stdio burst | 1.0050 | 0.9466–1.0405 | Fail |
| writev burst | 0.9778 | 0.9667–0.9882 | Pass |
| pipe ping-pong | 1.0141 | 0.9994–1.0234 | Fail |
| epoll pipe loop | 0.9892 | 0.9876–0.9935 | Pass |
| compute | 1.0017 | 0.9991–1.0036 | Pass |
| fork | 0.9951 | 0.9917–0.9983 | Pass |
| fork/exec | 0.9980 | 0.9927–1.0039 | Pass |

The report-producing test exited zero after 544.75 seconds, which means the
report completed, **not** that promotion passed. Stdio requires upper <1.00;
pipe ping-pong requires upper <=1.02. Both failed. The runtime default stays
legacy, and no retry or threshold relaxation closes these failures. Scoped
guest cleanup was verified; Carrick SHA-256 remains
`166143994b2502b38687b63deda3106da1e1d720e2c8d21d4faf576ae35f6086`.

The boundary improvement is real but insufficient evidence of broad benefit.
Return to the existing inotify scaling decomposition to rank the residual
watch/write/concurrent costs against fresh Docker before expanding transport
work. `inotify09`, the <=2x requirement, and all signed promotion gates remain
open.

### Fresh inotify component scaling after transport rejection

At `763a75bb7`, rebuilt the existing clean-room `perf_inotify09_scale` probe
and ran it first under the unchanged signed Carrick artifact, then under native
ARM64 Docker, both with the pinned LTP image above and `/bin/sh -c` invocation.
Carrick used the harness's unlimited trap count and host filesystem. Both runs
exited zero, all 25 phase/scale rows reported 21 complete samples, and both
reported `probe_complete=1`. Raw streams had no stderr diagnostics. Probe source
SHA-256 is `dfc7bf01aa7aa4ba31447842144521eb014c425bc6eebf1da03da299b7fb9be3`;
ELF SHA-256 is `87dd1362c7696d1c15289cf134729fb73a12c4fb3fed7ef7d5cd7ea00b9460a7`.
Carrick SHA-256 remained unchanged. Full outputs are retained as
`scale-current-carrick.out` and `scale-current-docker.out`.

| Phase, scale 65,536 | Carrick ns/iteration | Docker ns/iteration | Ratio |
| --- | ---: | ---: | ---: |
| watch churn | 4660 | 998 | 4.67 |
| write/seek | 6145 | 471 | 13.05 |
| persistent-watch write/seek | 6217 | 587 | 10.59 |
| serial composition | 11931 | 1581 | 7.55 |
| concurrent components | 8641 | 1138 | 7.59 |

Costs are approximately flat per iteration at the larger scales. These results
identify ordinary write/seek as a pathological component independently of
watch churn or LTP fuzzy synchronization. They do not prove which internal
function owns the remaining cost. The next attribution target is write/seek,
including residual metadata queries and its dispatch cost; adding a persistent
watch changes Carrick's large-scale result by only 72 ns/iteration. No runtime
budget or acceptance gate is relaxed.

### Residual metadata attribution

`hvpatch-write-metadata-stacks.d` captured 553,136 Darwin fstat events with
zero DTrace errors and its ten-second bound reached. Of those, 552,982 shared
the write hot-path stack. The raw capture is `write-metadata-stacks.trace`.
This trace perturbs execution and supplies no timing evidence.

Offline symbolization inferred image base `0x1008f4000` from the final Rust
thread-start frame and cross-checked the write dispatcher frames. LLDB
disassembly of the unchanged binary places stack return address `0x100cc7190`
at unslid `0x1003d3190`, immediately after the call to
`FsState::record_host_sparse_write` at `0x1003d318c`. This identifies sparse
extent bookkeeping as the dominant residual fstat caller, rather than the
already-cached dentry invalidation path. That function still calls
`host_file_identity(fd)` on every tracked write. The next correction can reuse
the live owned descriptor's immutable inode identity while preserving mutable
extent updates, aliasing, and unlink/replacement semantics.

### Owned identity reuse for sparse writes

Production commit `ccc42d7ad` changes sparse-write bookkeeping to accept the
owned `HostFdRef` and reuse its cached immutable inode identity. Sequential and
positional writes retain the owner through extent publication. Mutable extents
are still updated on every successful write. Ten sparse tests, including a new
alias/unlink/replacement/truncate case, and all 24 kernel-example contract tests
passed. The prior trace supplies the structural red evidence.

Signed artifact: SHA-256
`5ac057b96842305f771b7a2b5835dc33c95a4124cafa77b87710e98149916778`,
CDHash `f073d32e82a0352662651dbfcb279e5520afd3cd`, UUID
`E6533A16-C092-345C-BE5B-70454838EBB2`, hypervisor entitlement true and
`__dof_carrick` present. Repeating the bounded metadata trace produced 167 fstat
events, zero errors, and bound reached, versus 553,136 before the fix. The
trace is `write-metadata-cache.trace`; its timing is not performance evidence.

The unchanged scaling probe then completed uninstrumented with all rows and
`probe_complete=1`, empty stderr, exit zero. At scale 65,536, write/seek improved
from 6,145 to 5,713 ns/iteration (7.0%); persistent-watch write/seek was 5,792,
watch churn 4,666, serial composition 11,501, concurrent components 8,467.
Full output: `scale-sparse-cache-carrick.out`. Against the fresh pre-fix Docker
measurement of 471 ns, write/seek remains 12.13x. This closes the demonstrated
repeated identity-query defect, not the runtime-ratio failure, full inotify09,
or signed probe/smoke/full acceptance.

Full LTP follow-up on this same signed artifact, `conf-20563-s00`, timed out
at 40.256 seconds against the unchanged 40-second declared budget. The harness
classified it `FAIL TIMEOUT [blocked]`; both raw streams were inspected. The
earlier adaptive 23-second cutoff was diagnostic only. No retries were enabled,
and the cached Linux oracle remains 1/1. The sparse-write optimization therefore
has measured component impact but does not close the original workload.

The signed `write_seek_contract_budget` binding subsequently passed at scales
1, 8, 32, 128, with zero preparatory host position queries at every scale.
The unsigned entitlement negative control passed and both scoped cleanup
counts were zero. Receipt: `sparse-cache-write-seek-signed.jsonl`. The first
attempt failed before guest execution because `CARRICK_OBSERVATION_SOURCE`
was omitted; the qualified invocation supplied SHA-256 of `git archive HEAD`
at `ff25eef96`,
`7c88ac4f90d74db502844f61cfad936d358e092c9300deba1883ac54ec20515d`,
and the pinned LTP image. This is a signed instrumented test artifact, distinct
from the release CLI timing artifact; it is not full probe-gate acceptance.

### Repair of sustained service join state

The USDT-only control reproduced missing join state with no host syscall
clauses. Moving syscall-number selection from predicate to action did not fix
it (252,147 selected begins despite 909,322 hot begin events). Retaining the
thread-local identity and using nonzero inactive state `2`, rather than
zero-clearing every field on every service, then tracked 912,664 selected begins
with zero nesting, mismatches, or DTrace errors. This isolates the script's
state lifecycle as the failure mechanism; it does not establish a runtime
ownership bug. Receipt: `inotify-join-retained-state.trace`.

Applying the same correction to the full host-call join also passed its
existing checks (`inotify-join-fixed.trace`). Host counts now attribute one
Darwin lseek per guest lseek and one Darwin write per guest write, with only
one fstat in the write population. This is a bounded, highly instrumented
capture, not a runtime-ratio result. Complete per-host-call timing and explicit
boundary-censored window accounting remain to be added before calling it the
requested comprehensive timed attribution report.

### First reconciled service and host-call timing

`inotify-timed-host-join.trace` adds host entry/return wall and vtimestamp CPU
timing, service CPU timing, begin/completion/clear counts, and boundary-open
counts. Per-syscall service and host populations reconciled in this capture, but the
global scalar selected counter later proved inconsistent (722,435 versus
722,625 summed begins). This capture fails the new strict report validator;
every open-window count was zero, with no host/service mismatches or DTrace
errors. This is diagnostic instrumented timing, not a performance gate.

Write service CPU totaled 612,090,352 ns across 180,674 calls; host write CPU
was 268,485,769 ns (about 44%). Seek service CPU totaled 156,388,964 ns across
180,650 calls; host lseek CPU was 34,174,029 ns (about 22%). Service wall times
were much larger, demonstrating substantial tracing/scheduling perturbation;
wall-minus-CPU must not be called pure scheduler delay. These proportions
identify both native write cost and non-host-call service work as remaining
contributors. VM entry/return outside the service window is still unmeasured,
and this capture does not justify claiming a complete syscall round-trip split.


### Drained accounting and native Linux comparison (2026-09-21)

Replaced the concurrently incremented scalar selected counter with a DTrace
count aggregation. Admit service windows for eight seconds and allow two
seconds to drain; reject any remaining open windows. The first aggregate-only
capture was correctly rejected with one open write at the ten-second cutoff.
A subsequent drained capture reconciled 574,075 services and all host-call
windows, with no join errors. `inotify-accounting-drained.trace` and its JSON
report preserve the evidence. The first drain invocation mistyped the image
digest and failed before guest execution; the corrected invocation succeeded.

Within these instrumented service windows, non-host-syscall CPU totals rank
add-watch (309 ms), write (263 ms), remove-watch (100 ms), seek (97 ms).
Write additionally spends 215 ms in host calls. This points to watch installation
and write service work for the next focused profile; it still excludes VM
transitions and cannot establish the full round-trip overhead ranking.

Docker was stopped; launching Docker restored the native aarch64 oracle.
Qualified bpftrace 0.20.2 and captured the same pinned LTP image using the new
`scripts/bpftrace/inotify-service-time.bt`. The full Linux test passed with
3,000,000 calls each to add-watch, remove-watch and seek, and 3,000,034 writes.
Entries equal returns, all open counts and bad joins are zero, and no timeout
or lost-event diagnostic appeared. Mean instrumented elapsed syscall times:
add-watch 675 ns, remove-watch 607 ns, seek 274 ns, write 608 ns.
Raw output and stderr: `inotify-linux-service-time.{out,err}`.

These Linux elapsed measurements cannot be subtracted from Darwin CPU times:
the clocks, instrumentation and populations differ. Uninstrumented end-to-end
runs remain the ratio gate. No new full-inotify09 speedup or conformance parity
is claimed. Next: account for VM transitions, profile the dominant service
regions, then implement one contract-backed change and remeasure untraced.


### Whole-workload attribution check (2026-09-21)

On the unchanged release artifact (SHA-256
`5ac057b96842305f771b7a2b5835dc33c95a4124cafa77b87710e98149916778`),
`inotify-user-ranking.trace` sampled the harness-configured syscall path using
the existing carrier CPU script. Its emitted image base is `0x10291c000`.
The largest retained stack (14,221 samples across printed slices) passes through
`applevisor::Vcpu::run`; this includes guest execution/spinning and must not be
classified as pure transition overhead. The script truncates each slice to its
60 largest stacks, so retained counts are not a complete population or precise
whole-run share. This corroborates the earlier opaque guest/HVF bucket rather
than adding evidence for a particular runtime fix.

`inotify-whole-cpu.trace` completed its diagnostic receipt with no DTrace errors:
4,796 samples, 359 user and 4,437 kernel. Two unresolved kernel PCs account for
2,388 and 1,894 samples. The installed KDKs are 27.0 while the running kernel is
27.2.0 (`xnu-13432.40.144.0.1~53`); assigning those PCs names from the installed
KDK would be unsupported. Both guests were deliberately bounded at 12 seconds;
neither trace is an LTP pass. Scoped process inspection found no remaining
`carrick run`/`carrick trace` processes before resuming the public probe gate.

Next attribution work must isolate host-dispatch transition cost with the
existing finite `perf_trap_floor host-dispatch` reduction and qualified probes,
not equate time under Vcpu::run with host overhead. Meanwhile the restored live
Docker oracle permits closing the previously skipped signed gate observations.
