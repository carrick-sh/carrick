# Native-lane performance: state of play

**Date:** 2026-08-01 · **Branch:** `main` · **Scope:** Darwin/aarch64 native DSR
(`--exec-backend native`, the shipped default). No VMM/HVF/KVM/bhyve behaviour is
in scope.

> The FreeBSD native x86 bring-up work (`1b55b4b0`, branch
> `perf/native-xstate-transfer`) is unrelated and still open. Its caveat stands:
> `neutral-domains` remains opt-in — do not make it the production default until
> Tasks 43, 55 and 58 close.

## The goal

**Make carrick's emitted code materially faster — close the ~12x steady-state
execution penalty.**

The bar is *within 2x of native-arm64 Docker* on the same work. We are at **3.8x**
on compute (was 10.9x at the campaign's start; the phase ladder of
`docs/superpowers/specs/2026-08-01-steady-state-block-boundary-tax-design.md`
runs `bb17be5e` 5.9x -> `69754d31` 4.8x -> `e743cd8f` 3.8x, each with census,
wall, suite and conformance-smoke gates in the commit),
~13.6x on a cold build (translation-bound; untouched by these phases), and ~82x
on a filesystem walk (was 128x; the fs workstream's three commits `810bc6f4` +
`9c5fc386` cut 1,541 ms to 987 ms, and the surviving term is attributed with
file:line precision in task notes and target/perf/fswalk-amp3.raw - the
dispatch-level resolution stack, not the backend open). Carrick's premise
is running unmodified Linux binaries at host-native cost, so this number is the
product, not a metric about it — and people will benchmark us on whatever workload
they choose, not the one we tuned.

Codegen is the goal because it is the only term that no other strategy reaches.
Translation caching, AOT, and cross-process sharing were each sized this session
and all leave ~10-11.5x, because steady-state execution is ~12x *independently* of
how the code got there.

**The census exists now** (2026-08-01, `df14c939`): compute runs in Direct
(identity) mode, 68% of JIT-resident CPU was DSR-inserted, split indirect-exit
~30% / virtualized-register templates ~20% / entry guard ~13%. Phase 1 (the
reserved-resident x19 template, `bb17be5e`) removed the template dances and took
compute 10.9x -> 5.9x. The staged plan and its gates live in the design doc
above; Phases 2 (trusted-entry chaining) and 3 (indirect-lookup slimming) target
the two remaining inserted-word classes.

## Why the previous framing has to be dropped

The campaign that preceded this optimized against a single workload — a cold
`go build` — and generalized conclusions from it that do not hold elsewhere. A
cold build is *translation*-dominated (~800k translations across ~70 short-lived
processes). Steady-state compute is *emitted-code*-dominated (translation is
noise; the same blocks run thousands of times). The 2026-07-29 CPU budget's
"codegen is NOT the biggest bucket" is true of the build and was wrongly promoted
into a campaign-wide ranking that deprioritized codegen.

## Where we actually stand

`scripts/perf/workload-spread.sh` — five workloads, both engines, strictly serial
phases, in-guest timing windows on both sides so container setup is excluded
symmetrically. Measured on macOS 27 / t8132 / Apple Silicon (4 Performance +
6 Efficiency cores — `hw.logicalcpu` is *not* homogeneous), against
`localhost:5005/carrick-go-conformance:1.24`.

| workload | carrick | docker | ratio |
|---|---|---|---|
| startup (`true`) | 37 ms | ~0 ms | 37x (37 ms absolute — not a problem) |
| **compute** (8M-iteration awk loop) | 418 ms (was 1,196) | 110 ms | **3.8x** (was 10.9x) |
| **fs-walk** (`find` over the Go tree) | 1,541 ms | 12 ms | **128x** |
| build, cold GOCACHE | 11,550 ms | ~950 ms | ~12-13.6x (translation-bound) |

There is no workload where carrick looks good. The build is a *composite* of the
two problems above rather than a problem of its own.

## The finding that reframes the work

Decomposing the compute case (full detail in
`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md` §6):

```
carrick   wall 1,208 ms   children user 1.19 s   sys 0.03 s
docker    wall   109 ms   children user 0.10 s   sys 0.00 s
```

**~12x user CPU, both engines CPU-bound.** Not blocking. Not syscalls. And not
translation — `CARRICK_DSR_PROFILE` reports only 2,066 translations and 2,907
gateway entries across the entire 1.2 s run. Each block executes ~4,000 times, so
the cost is emitted code *running*, not code being produced.

This also corrects a number repeated throughout the older docs: "guest
instructions are only ~1.15-1.55x Docker" compared carrick's *share of sampled
CPU* in guest-shaped words against Docker's *total* CPU. Like-for-like it is ~12x.

## Settled — do not re-litigate

Each was measured, not argued. Evidence in
`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md` unless noted.

**Refuted mechanisms:** parallelism deficit (both engines ~2.5x on 10 CPUs);
4K-on-16K page granule (`Auto` already resolves to 16k, identical fault counts);
per-task kernel VM lock (XNU splits anon mappings at 128 MiB, each with its own
rw-lock); "carrick's memcpy causes the fault term" (JIT first-touch is 2.08% of
zfod).

**Already shipped — do not rebuild:** COW/file-backed guest *image* mapping.
`map_prepared_region_extent` does this in production and guest-image zfod is
**11**. (`map_prepared_for_plan` is a test-only helper; its `dead_code` marker
misled two separate analyses into believing the path was dead.)

**Tried and rejected on measurement:** pre-sizing the `recovery` Vec (+54%
allocation — it is retained, so over-allocation is retained too); thread-local
scratch reuse for it (-2%, inside the instrument's noise); the exit-target literal
pool (correctly reverted at `d4292368` — `movz`+3x`movk` is serially dependent at
~4 cycles, the same as the `ldr` that replaced it, and the pool adds a D-cache
access); a persistent AOT cache (+285% warm, 0 units published);
`MADV_WILLNEED` / `mlock` / `MAP_POPULATE` as populate primitives.

**Already optimal:** the direct-link fast path. `DirectLink.slot` is a branch in
the block body targeting the stub label; patching it jumps straight to the target,
so control never enters the stub. A patched link is `b <target>` with zero context
stores.

## Measured and true

- **Translation redundancy is 4.04x cross-process, 1.00x intra-process**
  (433,249 translations over 107,320 distinct guest VAs). The per-thread block
  cache is perfect. 4.04x is an upper bound — a fixed PIE base aliases VAs across
  binaries. Instrument: `CARRICK_XLAT_CENSUS_DIR`.
- **73% of carrick's heap traffic is the DSR block assembler**, allocated fresh
  per translated block. Instrument: `--features alloc-census` (dhat).
- **The shared-translation lane is ~90% of a persistent AOT cache.** Its
  `TranslationUnitKey` is fully content-addressed and stable across runs; only the
  *publication path* is broken — `claim_recording` requires a second sighting, and
  across three runs the cache held exactly one key. Fix or rewrite it; do **not**
  delete it (an earlier recommendation in this campaign to delete it was wrong).
- **`zero_backing` mprotect amplification is fixed** (`d2ba0f93`): 236,464 host
  `mprotect` calls against 8 guest calls, now 6,665. Worth 2.1% of guest CPU — the
  only performance change banked in this campaign.

## Open, ranked by what it settles

1. **DONE — the census exists and the ladder it ranked is landed** (phases
   `bb17be5e`..`e743cd8f`; every record in
   `docs/perf-results/native-dsr-shape-census.jsonl`). What remains on compute is
   the dispatch's serial load chain (cache-base/tag/`ldar`), with two bounded
   levers queued: entry packing for `ldp`, and a WRITTEN-ARGUMENT-FIRST
   relaxation of the generation `ldar` to a plain load.
2. **fs-walk, now ~82x (was 128x).** Three landed cuts: the stat cache consulted
   after dirfd resolution, child sizes carried out of the FIFO-probe stat, and
   non-creating guest opens served from ONE contained openat with fd-derived
   metadata (`810bc6f4`, `9c5fc386`). The surviving ~27.7k host opens/run are
   the DISPATCH-level resolution stack (anchor re-verify at fs.rs:4516,
   validate_parents_fast, canonicalize probes, and child_names re-walking a
   just-opened directory); the next slice - dirfd-anchor trust with generation
   invalidation + passing the opened fd into directory materialization - is
   specified in the session task notes.
3. **Whether the 2x bar is reachable at all**, given steady-state is ~12x.

## Decisions that need a human

- Does the 2x bar apply to cold builds specifically, or to representative
  workloads? This changes the ranking completely and needs no code to answer.
- Is a persistent on-disk translation cache acceptable architecturally
  (staleness, disk growth, GC)? The key already carries `translator_abi`, so stale
  entries miss rather than corrupt.

## Instruments, and the ways they lie

Kept deliberately — each cost real hours. Fuller notes in AGENTS.md.

- `ustack()` on this workload **does not fail, it lies**: ~70 self-re-exec'd
  processes with independent ASLR slides, nearly all dead at DTrace END, so
  surviving frames resolve against the *wrong* image and print plausible-but-false
  symbols. The tell is uniform counts plus one address symbolizing differently in
  different stacks.
- `fbt::vm_fault:entry` is listed by `dtrace -l` and **never fires**: FBT sees the
  exported `_vm_fault` (an alias of `_vm_fault_external`) while the trap path calls
  the local `_vm_fault_internal`, and FBT exposes no local symbols on this build.
  Check the KDK dSYM for a local twin before concluding a path is dead.
- Kernel frames can be **symbolizer aliases** — `IORWLockUnlock` *is* `lck_rw_done`
  at one address, so an "IOKit" frame in a VM profile is plain rw-lock traffic.
- `execname` scoping silently tracks nothing once two arms are built under
  different binary names.
- The **allocation census resolves large effects only**: process coverage varied
  23/25/34 across identical runs, because a process that `execve`s never drops the
  profiler. That variance swamps anything under ~10%.
- Anything measuring per-fault or per-operation cost must **pin core class**. A
  GOMAXPROCS sweep changes threads, concurrent processes, *and* which cores run
  the work; that confound produced a confident wrong conclusion here once already.

## Working notes

Durable lessons live in the agent memory directory, one file per lesson, indexed
by `MEMORY.md`. Add to it when something turns out to be non-obvious, and correct
or delete entries that turn out wrong. The operating rules — the overhead bar,
opt-out defaults, no backward compatibility, Rust-first tooling, and the dtrace
traps — are in AGENTS.md.

One pattern worth carrying forward: this campaign produced four reverts, and every
one came from acting on a mechanism *inferred* from a correlation rather than
measured. Hot PCs in `memmove` became "carrick's own copies". A `dead_code`
attribute became "the path is dead". A concurrency sweep became "lock contention".
An emitted-word census became an execution profile. The measurements were sound
each time; the inferences ran ahead of them.
