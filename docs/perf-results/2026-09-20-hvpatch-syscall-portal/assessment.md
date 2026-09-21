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
