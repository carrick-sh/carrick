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
