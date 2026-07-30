# Native/aarch64 DSR: where the go-build CPU actually goes (2026-07-29)

Cold `go build` of a hello-world with a fresh `GOCACHE` — the reference
workload, so the work is the Go toolchain compiling from scratch. Two 60 s
`dtrace` runs on the same binary (`a4b1555a`), each printing its own
denominator: `profile-997` fires per CPU while a tracked pid is on-CPU, so
samples/997 IS aggregate CPU-seconds.

Tracking is by carrick's own `carrick*:::dsr-cache-*` lifecycle probes under
`dtrace -Z`, never `execname` — `execname` is the binary basename and silently
tracks nothing the moment two arms are built under different names.

## Run 1 — `scripts/dtrace/native-whole-cpu-budget.d`

**43,554 samples = 43.69 aggregate CPU-seconds.** WORKLOAD_NS 17.09 s, BUILD_OK.

| CPU-s | share | bucket |
|---|---|---|
| 26.09 | 59.7% | user (translated code plus host runtime) |
| 13.42 | **30.7%** | kernel, NOT a syscall or mach trap — faults, scheduling, interrupts |
| 4.04 | 9.3% | kernel inside a named syscall |
| 0.14 | 0.3% | mach traps |

Faults on the same run: **2,204,683 address-space**, **1,787,838 zero-fill**,
77,723 COW. That is ~6 µs of kernel per address-space fault if faults dominate
the 13.42 CPU-s, which is the right order for a macOS fault.

Every named syscall, on-CPU kernel time:

| CPU-s | share | syscall |
|---|---|---|
| 0.882 | 2.02% | `openat` |
| 0.877 | 2.01% | `psynch_cvwait` |
| 0.312 | 0.72% | `mprotect` |
| 0.310 | 0.71% | `psynch_cvsignal` |
| 0.305 | 0.70% | `fork` |
| 0.230 | 0.53% | `read` |
| 0.161 | 0.37% | `close` |
| 0.129 | 0.30% | `poll` |
| 0.117 | 0.27% | `execve` |

## Run 2 — `scripts/dtrace/native-user-module-split.d`

**34,924 samples = 35.03 CPU-s**, user 24.77 CPU-s (70.7%). `umod()`/`usym()`
attribution of every sampled user PC. Unresolved PCs are the `MAP_JIT` code
cache; that identification is what an earlier read got wrong by assuming they
were host code.

| CPU-s | share of total | bucket |
|---|---|---|
| 18.52 | **52.9%** | JIT code cache — translated guest + inserted words |
| ~4.9 | ~14% | carrick host user code |
| ~2.3 | ~6.6% | system libraries (`malloc` 2.4%, `_platform_memmove`/`memset` 2.6%) |
| ~10.3 | ~29.3% | kernel (corroborates run 1's 30.7%) |

52.9% independently reproduces the earlier campaign figure for the JIT share,
measured on a different day with a different script.

Hottest resolved host symbols:

| CPU-s | share | symbol |
|---|---|---|
| 0.697 | **1.99%** | `sha2::sha256::compress256` |
| 0.032 | 0.09% | `carrick_dsr::cache::PageGenerationTable::observe` |
| 0.031 | 0.09% | `ThreadTranslator::translate_read_mostly` |

SHA-256 in the host runtime costs as much CPU as all `openat` kernel time.

## What this settles

**Two standing hypotheses are real but small.** `openat` kernel time is 2.0% of
CPU, so the ~291-host-opens-per-guest-open amplification cannot be a CPU lever
however bad it looks (it may still cost wall latency). Condvar churn
(`psynch_cvwait` + `psynch_cvsignal`) is 2.7%, and most of `cvwait` is waiting,
not work that could be deleted.

**The per-block-entry prologue is not the prize, and three measurements say so
rather than one.** Paired screens, each ten pairs:

| change | mechanism verified | result |
|---|---|---|
| exit-target literal pool | `dsr:x17-materialize` 29.1% -> 9.7% of emitted words; 41 MB less JIT per build | no win |
| gateway phase claim (`a4b1555a`) | one word off every block entry | 5/10 wins, median 1.0030, p=0.62 |
| whole guard CHECK removed (measurement arm) | 4-word address chain **and** the `ldar` acquire gone | 6/10, median 0.9867, p=0.38 |

Deleting the entire per-block-entry stale-code check is worth ≤2.6%. The
ranking that pointed there came from sampled-instruction share, which
over-collects on the first word after a taken branch — and a block's first word
is exactly that for every direct-linked jump into it. **Rank by
(events/second x words/event) and confirm with a paired A/B; never by sample
share alone.**

Each of those cuts removed roughly one of ~19 executed inserted words in its
path. One nineteenth of 52.9% is ~2.8%, at or below the instrument floor below —
so all three were unmeasurable *by construction*. Moving the JIT bucket needs a
change that removes MANY words at once, not one.

## Instrument floor, measured

A NULL screen — the same binary copied to both arms, 8 pairs:

| metric | ratio sd | smallest resolvable effect at n=8 |
|---|---|---|
| wall | 5.54% | 3.22% |
| CPU-seconds (`7c701293`) | 3.86% | 2.25% |

CPU-seconds is ~30% tighter, not several-fold. The null screen also exposed a
defect in the screen itself: **whichever arm runs SECOND is ~1% slower with
identical binaries** (median 1.013 wall, 3/8 "wins" for arm B). Every screen in
the table above ran the change second, so each was biased against its own change
by about the size of the effect being chased. Run A-B-B-A and average each arm's
two positions.

Practical rule: **do not chase a change whose predicted effect is under ~5%**
at this pair count, whatever its mechanism gate says.

## Ranked next work

1. **Kernel non-syscall time, ~30%.** 2.2 M address-space and 1.79 M zero-fill
   faults. Attack fault COUNT — first-touch pages, arena reuse across guest
   processes, and the fork path, which pays guest address-space setup in host
   faults per `clone(2)`. Emitted JIT code is NOT the driver: the whole build's
   emitted code is 36,573 first-touch pages, 2.08% of the zfod faults.
2. **JIT'd code, 52.9%** — but only via a change that removes several executed
   words per event. The concrete candidate is extending the compact biased
   lowering to register-offset addressing: `compact_biased_form` rejects
   `MemoryEffectiveAddress::RegisterOffset` outright, so every array-indexed
   access (pervasive in Go) takes the 8-word general path instead of ~3 words.
3. **carrick host user code, ~14%**, starting with `sha256::compress256` at 2.0%.
4. Named syscalls, 9.3% in total, nothing above 2% — cannot move the headline.

## Run 3 — `CARRICK_DSR_PROFILE=1` event counts

The budget above says WHERE the CPU is; this says WHY, and it re-ranks the list.

**Caveat first:** profiling slows this workload enough that the run hit its
200 s timeout instead of finishing in ~17 s (`rc=125`), so the totals are a
large partial sample and the *time* fractions are perturbed. The COUNTS and the
per-process structure are what the conclusions below rest on.

Aggregated over 47 guest processes:

| metric | value |
|---|---|
| translations | **799,494** |
| gateway entries | 1,018,915 |
| code-cache lookups / hits | 799,570 / **76** |
| invalidated blocks | 0 |
| translation time | 4.87 s = 34.3% of profiled thread CPU (decode 15.3%, emit 18.6%) |

Per-process translation counts: ~40 processes each translating **20,000–53,000
blocks** (top: 53,173 / 46,874 / 46,835 / 43,029 …), and the top 40 account for
780,788 of the 799,494 translations.

Those ~40 processes are the per-package `compile` invocations of one `go build`
— **the same toolchain binary, re-translated from scratch in every process.**
The distinct block set across the whole build is a small fraction of 799,494.

Read the 76/799,570 hit rate carefully: `CacheLookups` is incremented per
*translate request*, and requests only reach the resolver when the upstream
one-entry cache and direct-binding cells miss (`one_entry_hits` 491,878,
`direct_resolver_exits` 512,505 on the same run). So the 0.01% is a statement
that resolver requests are almost always for genuinely-new blocks — NOT that
intra-process reuse is broken. The reuse that is missing is **across
processes**.

## Why this explains the three failed codegen cuts

Translation is on the order of a third of the profiled thread CPU, and it scales
with (processes x blocks-per-process) when it could scale with (distinct
blocks). No amount of shaving executed words changes that term at all — and the
executed-word cuts each removed ~1 of ~19 words in their path, which is below
the instrument floor. Both halves of the disappointment have the same root: the
work is dominated by translating code that was already translated in a sibling
process, and by kernel faults, not by how tight the emitted code is.

## Re-ranked, with the evidence for each rank

1. **Cross-process (container-lifetime) translation reuse.** 799,494
   translations across ~40 processes running the same binary. This is already
   the repo's stated direction (`72b5a419` "plan container-lifetime translation
   sharing", `92060018` "scope translation cache to one container"), and the
   blocker is known and measured: shared translation is currently **17–50x
   slower** than translating fresh, which is why it is off. Indexing
   direct-binding records by edge took the worst case from >300 s to 64–76 s;
   it needs to get under "translate it again" to be worth switching on.
2. **Kernel non-syscall time, ~30%** — 2.2 M address-space and 1.79 M zero-fill
   faults. Emitted code is only 2.08% of the zfod faults, so the mass is guest
   anonymous memory plus the fork model.
3. **Emitted-code SIZE, not speed** — `emit` is 18.6% and `decode` 15.3% of
   profiled thread CPU. That reframes the literal pool: its 41 MB / 20%
   reduction in emitted words was a real win against *translation* cost even
   though it bought no execution speed. Size-reducing codegen is worth more than
   cycle-reducing codegen on this workload.
4. carrick host user code, ~14%, starting with `sha256::compress256` at 2.0%.
5. Named syscalls, 9.3% total, nothing above 2%.

## Run 4 — why shared translation loses: a 171x gateway-exit explosion

The rank-1 item above assumed the blocker was slow unit LOADING (task #19 took a
worst case from >300 s to 64–76 s by indexing direct-binding records by edge).
That assumption is wrong. A four-arm bisect of the three env flags, one profiled
run each, same binary, `CARRICK_DSR_SUPERBLOCK=8`, all BUILD_OK:

| arm | wall s | translations | `direct_resolver_exits` | gw entries / translation | thread CPU s |
|---|---|---|---|---|---|
| `ARTIFACT_SPIKE=1` | 13.8 | 1,196,909 | 778,739 | 1.5 | 30.6 |
| `DIRECT_BINDINGS=1` | 14.4 | 1,217,406 | 778,636 | 1.5 | 31.7 |
| **`SHARED_TRANSLATION=1`** | **57.6** | 1,042,109 | **133,339,214** | **129.0** | 156.8 |
| `SPIKE` + `SHARED` | 55.1 | 1,031,358 | 124,839,345 | 122.1 | 153.7 |
| all three | 88.0 | 1,030,325 | 127,622,799 | 125.0 | 210.4 |

`CARRICK_DSR_SHARED_TRANSLATION=1` **on its own** costs 4.2x wall, and the
mechanism is unambiguous: `direct_resolver_exits` goes **778,739 -> 133,339,214,
a 171x increase**. Every direct branch takes a full gateway round-trip to
re-resolve its target instead of jumping through a bound direct link. The
per-round-trip phases scale with it — `phase_finish_exit_ns` 2.46 s -> 44.1 s,
`phase_prepare_index_ns` 2.53 s -> 25.5 s, `phase_loop_quiesce_count` 1.84 M ->
134 M.

Neither of the other flags causes it and neither repairs it. `DIRECT_BINDINGS=1`
on top of shared makes things *worse* (88.0 s vs 55.1 s), which is the
direct-binding record scan of task #19 paying a cost it cannot recover here.

**And sharing is barely delivering reuse even so:** translations fall only
1,196,909 -> 1,042,109 (13%). A 13% cut in translation work does not begin to pay
for a 4.2x wall regression.

Correction to an earlier reading in this document's run 3: the `shared_unit_*`
counters (`shared_unit_lookups`, `shared_unit_hits`, `shared_unit_loads`,
`shared_translations_avoided`) exist in `ResolverStats` but are NOT among the
fields the `resolver-process` profile frame prints, so their absence from the
output is not evidence of zero hits. The 13% translation figure is the
independent evidence that reuse is not landing, and it stands on its own.

### What this changes about rank 1

Container-lifetime translation sharing has **two independent defects**, and the
one that was being worked was not the binding one:

1. **Enabling sharing collapses direct linking** — 171x more direct-resolve
   gateway exits. This is the 17–50x slowdown, and it is an emission/binding
   defect, not a cache-lookup cost. Fix this first; until it is fixed, no amount
   of load-path optimization can make sharing a win.
2. **Sharing avoids only 13% of translations** even when enabled, against the
   799,494-translations prize that motivated it (~40 processes each translating
   20,000–53,000 blocks of the same toolchain binary).

Emit the `shared_unit_*` counters in the profile frame before doing either, so
lookups, hits, loads and misses are observable rather than inferred.

## Run 5 — the 171x explosion, root-caused to 99.92% unbindable edges

### First, a correction to run 4

Run 4 said sharing was "barely delivering reuse" and a later commit said the
loaded units were "loaded and thrown away". **Both readings were wrong**, and the
arithmetic that refutes them was already available:

| | |
|---|---|
| translations, sharing OFF | 1,196,909 |
| translations, sharing ON | 1,031,914 |
| reduction | 164,995 |
| `shared_blocks_mapped` | 171,480 |
| **reduction / blocks mapped** | **0.96** |

The mapped blocks account for essentially all of the translation reduction.
Sharing works exactly as designed where it applies; it simply applies to only
**14.2%** of a process's blocks (3,176 mapped per successful load against 14,534
translations per process).

The mistake was using `cache_lookup_hits` (13 of 1,051,969) as a reuse measure —
after this same document had already explained that it is not one, because
lookups only reach the resolver for genuinely-new blocks. Do not read a
low-level miss counter as a statement about a high-level cache's usefulness.

### The real defect

With `CARRICK_DSR_SHARED_TRANSLATION=1` and `CARRICK_DSR_DIRECT_BINDINGS=1`
(57.3 s wall, BUILD_OK), the newly published direct-binding gauges say:

| counter | value |
|---|---|
| `db_owner_validation_failures` | **136,218,515** |
| `db_cas_wins` (edges actually bound) | 101,010 |
| `db_cas_losses` | 4 |
| `db_authority_validation_failures` | 0 |
| `db_publication_retries` | 0 |
| `direct_resolver_exits` | 136,321,369 |

**99.92% of every direct-resolver exit fails owner validation**, and only 101,010
edges are ever bound in the whole build.

`DirectBindingRegistry::classify_cold_exit` can bind an edge only if
`records_by_edge` contains `(source, target)` — that index is built from the
LOADED UNITS' manifest records, so **only edges the publishing process declared
can ever bind.** With the unit covering 14.2% of a process's blocks, nearly every
edge leaving shared code targets a locally-translated block that no manifest
declares, returns `MissingEligibleRecord`, and re-resolves through the gateway on
every single traversal. Shared blocks are the HOT ones, so those unbindable edges
are traversed ~780 times each: 136 M gateway round-trips.

This also explains why `CARRICK_DSR_DIRECT_BINDINGS=1` does not help (133 M vs
125 M resolver exits): the runtime binding path is reached and then declines,
because the limit is the manifest, not the cell machinery. And it explains the
architecture: loaded units are pinned `VM_PROT_READ | VM_PROT_EXECUTE` with the
MAXIMUM protection also set (`pin_loaded_translation_protection`), so shared code
can never be patched in place; it must indirect through writable per-process
cells, which is what `LoadedTranslationProtection::BindingCells` exists for.

### What has to change

Either (a) let an edge from shared code bind to a PRIVATE, locally-translated
target through a per-process cell — the general case the manifest cannot
pre-declare — or (b) raise unit coverage far enough that most targets are
in-unit. (a) is the real fix; (b) only moves the ratio.

Until one of them lands, container-lifetime sharing trades a 14% translation
saving for a 171x increase in gateway round-trips on the hottest code, which is
why it measures 4.2x slower and ships off.

## Run 6 — correcting run 5, and the actual localization

### Run 5's root cause was wrong, and a control arm refutes it

Run 5 read `db_owner_validation_failures` = 136,218,515 of 136,321,369 exits
(99.92%) as proof that shared-code edges cannot bind. Running the control that
should have accompanied it — `DIRECT_BINDINGS=1` with sharing OFF — refutes it:

| arm | wall | `direct_resolver_exits` | `db_owner_validation_failures` | `db_cas_wins` |
|---|---|---|---|---|
| bindings only, no sharing | **12.2 s** | 779,874 | 777,965 (99.8%) | 0 |
| shared + bindings | 57.3 s | 136,321,369 | 136,218,515 (99.9%) | 101,010 |

The failure ratio is ~99.8% in BOTH arms, and the fast arm binds nothing at all
(`cas_wins` = 0) while running in 12.2 s. `classify_cold_exit` is called on
EVERY `ResolveDirect` exit, and a locally-translated edge has no manifest record
by construction, so the counter tracks exits 1:1 and says nothing about why they
exploded. A ratio that is identical in the healthy and pathological arms cannot
be the cause — the control arm is what makes that visible, and run 5 did not run
one.

### What the exits actually are

Classifying each `ResolveDirect` by whether its source and target are shared
blocks (scratch counter, 513 reporting processes, sampled at 750,000 exits):

```
EXITSRC total=750000 shared_source=178 private_source=749822 shared_target=745608
```

**99.4% of the exploding exits TARGET a shared block, and essentially none
ORIGINATE from one** — the opposite of run 5's assumption. Locally-translated
blocks branch into shared code, and those edges never bind, so every traversal
takes a gateway round-trip. Shared blocks are the hot ones, which is why the
count reaches 136 M.

### Why a private -> shared edge cannot bind

`classify_cold_exit` yields a binding cell only when `records_by_edge` holds
`(source, target)`, and that index is built from the LOADED UNITS' manifest
records — so only edges whose SOURCE is shared code can ever be classified. A
private source block has its own emitted direct-binding stub and cell, but no
unit declares it, so `binding_eligibility` is `Err`, `direct_binding_target` is
never called, and the cell is never published.

Everything else on that path is already correct and does NOT need changing:
`target_cache_authority` and `direct_binding_target` both handle a shared target
properly, returning the loaded unit's authority and a
`DirectBindingTarget::shared_in_unit` descriptor. Only the eligibility gate
rejects the edge.

With sharing off this never bites, because every target is private and the
emitter can commit the link when the target is already translated; the 779,874
exits in that arm are the one-time cold resolves.

### The fix, and why it is not a one-liner

Publish the PRIVATE source's own cell for a valid target without demanding a
manifest record: the cell address and ordinal already arrive in the exit
metadata (`DirectBindingMiss`), and the target descriptor is already
constructible. What must be preserved is the ownership validation the manifest
currently provides — for a private source that means proving the cell lies
inside this process's private, writable cache and within the exiting block's own
stub envelope, plus ensuring `invalidate_target` clears these cells when the
shared target's generation is invalidated (the descriptor carries the unit and
generation, so the existing clear path is the place to check).

That is a protocol extension in code governing cross-process code invalidation,
where a mistake is silent wrong-code execution. It is specified here rather than
attempted at the end of a long session.

## Run 7 — retracting half of run 6, and two more refuted hypotheses

### Run 6's source classification was invalid

Run 6 concluded "99.4% of exits TARGET a shared block and essentially none
ORIGINATE from one". **The second half is an artifact of the test.** The scratch
classifier compared `source` against `shared_blocks`, whose keys are block
STARTS — but `PlannedExit::Direct { guest, .. }` carries the guest PC of the
BRANCHING INSTRUCTION, and `emit_direct_exit` passes that as `source_guest`. A
shared block whose branch is not its first instruction is therefore counted as
"private source", which is almost always. `shared_source=178` measures nothing.

The `shared_target` half stands: targets ARE block starts, so **99.4% of the
exploding exits do target a shared block**.

### Two further hypotheses, both refuted by controls

| hypothesis | control | verdict |
|---|---|---|
| shared-code edges cannot bind (99.92% `owner_validation_failures`) | bindings-only, sharing OFF: same 99.8% ratio, 12.2 s, `cas_wins`=0 | **refuted** — the counter tracks exits 1:1 in both arms |
| superblocks are excluded from shared units, so loading one un-fuses hot code | fusion OFF, sharing OFF: 1,435,358 exits, 13.1 s | **refuted** — losing fusion costs 1.8x, not 173x |

| arm | wall | translations | `direct_resolver_exits` | gateway entries |
|---|---|---|---|---|
| fusion ON, sharing OFF | 12.2 s | 1,217,693 | 779,874 | 3,652,660 |
| fusion OFF, sharing OFF | 13.1 s | 1,870,324 | 1,435,358 | 5,128,236 |
| fusion ON, sharing ON | 61.2 s | 1,045,352 | 135,259,579 | 272,690,918 |

### What is actually established

- Enabling sharing multiplies direct-resolver exits ~173x and gateway entries
  ~75x. This is the whole cost; it is not translation, not fusion, not binding
  validation.
- Sharing delivers a 14% translation reduction, proportional to its 14.2% block
  coverage (reduction/blocks-mapped = 0.96).
- 99.4% of the exploding exits target a shared block.
- Private blocks emit `DirectExitEmissionPolicy::PrivateGateway`, an
  unconditional gateway exit with no cell and no baked branch; only portable
  (unit) blocks emit the cell-based `PortableUnitAuthority` stub. In the healthy
  arm direct exits are simply RARE (780 k for the whole build), and `cas_wins`
  is 0 — so cell binding plays no part in the fast path at all.

### The next measurement, stated so it is not guessed at again

Classify each `ResolveDirect` by whether the SOURCE PC falls inside a shared
block's `[start, end)` RANGE — not by equality against block-start keys — and
report source and target classes together. That distinguishes the two remaining
stories: flow bouncing between shared blocks whose cell stubs never bind
(`cas_wins` 101,010 against 136 M exits), versus private code repeatedly
re-entering shared code. They need different fixes, and three hypotheses have
already died for want of exactly this discrimination.

**Method note.** Four hypotheses in this investigation were refuted by a control
arm that took one run each, after being asserted on the strength of a single
correlated counter. The pattern is identical every time: a ratio measured only in
the pathological arm, never in the healthy one. Run the control in the SAME
commit as the claim.

## Run 8 — profiling it, which is what should have happened first

Runs 4–7 argued about WHICH COUNTER was big. None of them profiled the slow arm.
This does, with `dtrace` + `ustack()`, matched arms (identical settings except
`CARRICK_DSR_SHARED_TRANSLATION`, no `CARRICK_DSR_PROFILE` on either).

### Two instrument faults had to be fixed first

1. **The tracer was arming the hot probe.** `native-user-module-split.d` tracked
   pids on BOTH `carrick*:::dsr-cache-capacity` and `carrick*:::dsr-cache-event`.
   The latter fires per cache event — 136 M+ times with sharing on — so tracking
   on it made the USDT forwarder itself 14.4 CPU-s of the profile. Track only on
   `dsr-cache-capacity`, which fires once per process from
   `ProcessTranslator::new`.
2. **`ustack()` was unwalkable without frame pointers.** The first attempt
   produced semantically impossible chains — `oci_client::sha256_digest` calling
   `bad64::sysreg::ToPrimitive` calling `drop_in_place<Backtrace>` calling
   `fcvtzs_z_p_z` — with the SAME bogus tail on every stack, the signature of an
   unwinder scanning and snapping to nearest-preceding symbols. Rebuilding with
   `RUSTFLAGS="-C force-frame-pointers=yes"` (a codegen flag, so the
   `__DATA,__dof_carrick` USDT section survives — verified) produced coherent
   stacks. Do not read a `ustack` profile of this binary without that flag.

### Flat attribution, matched arms

| | sharing OFF | sharing ON | ratio |
|---|---|---|---|
| total | 32.72 CPU-s | 113.27 CPU-s | 3.5x |
| user | 22.20 | 56.52 | 2.5x |
| kernel | 10.52 | 56.75 | **5.4x** |
| carrick **host** code | 3.09 | **67.38** | **21.8x** |
| JIT cache | 18.01 | 10.11 | **0.6x** |
| system libs | 1.80 | 4.34 | 2.4x |

The JIT cache share goes DOWN in absolute terms. Sharing does not make
translated code slower — it moves the workload out of translated code and into
carrick's own host resolver.

### Where the host time goes

Stacks containing, as a share of all on-CPU time (user stacks capture 31.5 of
132.8 CPU-s; the remainder is kernel and JIT frames that do not unwind):

| CPU-s | share | stack contains |
|---|---|---|
| 19.71 | 14.8% | `ThreadTranslator::finish_exit_profiled` |
| 15.75 | 11.9% | `ThreadTranslator::translate_read_mostly` |
| **13.81** | **10.4%** | **`parking_lot::RawRwLock::lock_{shared,exclusive}_slow`** |
| 7.84 | 5.9% | `ThreadTranslator::prepare_entry` |

Top leaf: `RawRwLock::lock_shared_slow` at 10.83 CPU-s, **8.2% of all on-CPU
time**, with `lock_exclusive_slow` a further 2.2%.

Every stack is the same shape:

```
run_native_thread_loop -> run_native_dsr_thread_loop_profiled
  -> finish_exit_profiled (or prepare_entry)
    -> translate_read_mostly
      -> parking_lot::RawRwLock::lock_shared_slow
```

The kernel side corroborates it: the kernel leaves are `swtch_pri_continue` and
`psynch_cvcontinue` — scheduler and condvar blocking, which is what a contended
lock produces. (macOS/arm64 kernel stacks do not walk out of exception context,
so only leaves are available.)

### The answer

**Sharing is slower because every one of the 173x-amplified gateway exits takes
the process-wide `ProcessState` RwLock, and that lock goes to its parking
slow path.** The exit amplification is the primary cause; the RwLock is where
the amplified cost is actually paid, and it is the single largest identified
consumer in the slow arm.

That reframes the fix. Two independent levers now exist, and the second does not
require understanding the exit amplification at all:

1. Reduce the exits (still uncharacterised — see run 7's next measurement).
2. **Make the exit path not contend.** `finish_exit_profiled` -> `translate_read_mostly`
   takes a shared lock on every exit; a read-mostly fast path that avoids the
   lock entirely (or a per-thread cache checked before it) removes 10.4% of CPU
   in the slow arm regardless of why the exits are so numerous.

Caveats: the frame-pointer build is not the shipping codegen; user stacks cover
24% of on-CPU time; and this is one run per arm, not a paired screen.

## Run 9 — JIT-aware profiling, and a re-check of what we are aiming at

`ustack()` cannot walk translated frames: JIT'd guest code uses x29 as a guest
register, so there is no frame-pointer chain. Unwinding those samples costs
buffer space and aggregation slots to produce garbage, which is why run 8 landed
only 24% of on-CPU time in usable stacks.

`dsr-cache-bounds` (new) publishes each process's JIT cache host-VA range once at
creation, so `scripts/dtrace/native-jit-aware-profile.d` classifies a sampled PC
with two compares and invokes the unwinder ONLY for host frames.

Two things had to be right for the classification to mean anything:

* **The bounds must be inherited across fork.** carrick forks a real host process
  per guest `clone(2)` — ~50 for one go-build — and the child inherits the
  parent's JIT mapping. Marking the child tracked without copying its bounds put
  every forked child's translated samples in the "host" bucket.
* **Truncate generously and aggregate by NAME offline.** dtrace keys `usym`/
  `ustack` on `(pid, address)`, so one hot symbol fragments into ~50 entries
  across ~50 processes; `trunc(@leaves, 25)` discarded nearly all the signal and
  left a ranking that was an artifact of process count.

### The shipping configuration, 34.4 CPU-s

| CPU-s | share | bucket |
|---|---|---|
| 12.29 | **35.8%** | carrick HOST code |
| 12.21 | **35.5%** | JIT cache (translated guest + inserted words) |
| 9.85 | 28.7% | kernel |

Host leaves, aggregated by name (74% of the host bucket captured):

| CPU-s | share of total | leaf |
|---|---|---|
| 0.398 | 1.16% | `_platform_memmove` |
| 0.282 | 0.82% | `_platform_memset` |
| 0.244 | 0.71% | `sys_icache_invalidate` |
| 0.179 | 0.52% | `decode_spec` |
| 0.154 | 0.45% | `_xzm_xzone_malloc_tiny` |
| 0.152 | 0.44% | `emit::assemble_block_inner` |
| 0.145 | 0.42% | `BTreeMap::insert` |
| 0.137 | 0.40% | `sha2::sha256::compress256` |

### Are we aiming at the right thing?

**The host bucket is as large as the JIT bucket, and it is almost entirely
TRANSLATION.** `memmove` + `memset` + `sys_icache_invalidate` alone are 2.7% of
total and are pure mechanical cost of *emitting* code — copying words into the
cache, zeroing, and I-cache maintenance — all proportional to emitted BYTES.
Add `decode_spec`, `assemble_block_inner`, `BTreeMap::insert` and the malloc
traffic and the picture is unambiguous: carrick spends about as long PRODUCING
translated code as RUNNING it, ~800,000 times per build.

That confirms the ranking arrived at in runs 3–8 and contradicts the one this
campaign started with:

1. **Translation cost and reuse** — 35.8%, and the reason container-lifetime
   sharing matters. Also why emitted-code SIZE beats emitted-code SPEED here:
   size is what `memmove`/`memset`/`icache` scale with.
2. **Kernel, 28.7%** — dominated by faults (run 1: 2.2 M address-space faults).
3. **Codegen quality** — only part of the 35.5% JIT bucket, and three separate
   attempts measured ≤2.6% each.

Independent corroboration of a landed change: `sha256::compress256` is 0.40% of
total here against **1.99%** in run 2, a ~5x drop consistent with the 4.0x
hardware-backend speedup measured in isolation.

## Run 10 — A0 met: the amplification is entirely private -> shared edges

Run 6's source classification was invalid (it compared a BRANCH PC against
block-START keys). This redoes it the way the goal's A0 exit criterion demands:
`ProcessState::shared_guest_ranges` records each mapped shared block's guest
`[start, end)` from its `source_words`, and every `ResolveDirect` is classified
by binary-search RANGE containment of BOTH source and target.

Sharing ON, 49.8 s, BUILD_OK, 136,489,314 `ResolveDirect` exits:

| exits | share | class |
|---|---|---|
| 135,715,237 | **99.4%** | source private -> **target SHARED** |
| 733,764 | 0.5% | source private -> target private |
| 33,763 | 0.02% | source SHARED -> target SHARED |
| 6,550 | 0.005% | source SHARED -> target private |

**The control arm is built into the same measurement.** Sharing OFF totals
779,874 `direct_resolver_exits`; here the private -> private population is
733,764 — the same number. Enabling sharing does not change the normal exit
population at all. It ADDS 135.7 M private -> shared exits, and those are the
entire 173x.

Two further facts fall out:

- **Shared blocks barely exit at all** (40,313 combined, 0.03%). Their internal
  edges are patched at pack time by `patch_same_unit_direct_link`, so
  intra-unit control flow never reaches the gateway. The unit's own code is
  fine; it is the boundary INTO it that is not.
- **Every private -> shared edge re-resolves on every traversal.** 135.7 M
  exits against 175,558 mapped shared blocks is ~770 re-resolutions per shared
  block. Nothing binds that edge, ever.

### A0 verdict

Mechanism named: **a direct edge from privately-translated code into a
loaded shared block is never bound, so it takes a full gateway round-trip every
time it executes; shared blocks are the hot ones, so this is 99.4% of all
resolver exits.** Confirmed by control: the private -> private population is
unchanged between arms.

### What A1 has to answer

Private blocks emit `DirectExitEmissionPolicy::PrivateGateway`, an
unconditional gateway exit with no cell and no baked branch, and the emitter
never consults already-translated blocks (`committed_link` is cell-recovery
metadata, not an emit-time target). Yet private -> private edges resolve only
~0.7 M times for ~1.05 M translations — about once each — so SOMETHING stops
them re-resolving that does not apply to a shared target. Find that mechanism
and either extend it to shared targets or explain why it cannot be. Do not
guess: five hypotheses have already died here.

## Run 11 — A1 sized: 74,726 cold call edges into hot shared code

The A0 classification said 99.4% of the amplified exits are private -> shared.
That is meaningless until divided by the number of EDGES producing them, so both
classes now also count DISTINCT `(source, target)` pairs, and the private ->
private class is carried as the control.

Same binary, both arms:

| arm | class | exits | distinct edges | traversals per edge |
|---|---|---|---|---|
| OFF | private -> private | 782,054 | 440,578 | **1.8** |
| ON | private -> private | 734,116 | 481,368 | **1.5** |
| ON | private -> **shared** | 136,133,949 | 74,726 | **1,822** |

### There is no binding mechanism to extend — that was the open question

Private -> private edges resolve **1.8 times each**. They are cold. The healthy
arm is not fast because something binds its direct edges; it is fast because its
direct edges are almost never traversed twice. Enabling sharing leaves that
population untouched (1.5 per edge) and adds a population traversed **a thousand
times more often per edge**.

That closes the question A0 left open, and it rules out "extend the existing
mechanism": there isn't one. A binding path for these edges has to be BUILT.

### Why the shared edges are the hot ones

A unit is published precisely because its code RECURS across processes — so a
loaded unit contains, by construction, the hot code. Meanwhile
`source SHARED -> target private` is only 6,550, and `SHARED -> SHARED` only
33,763 (intra-unit edges are patched at pack time by
`patch_same_unit_direct_link`). So control does not leave shared code by a direct
edge at all: private code CALLS into shared code 136 M times over 74,726 call
sites, and returns by an indirect branch that is not a `ResolveDirect`.

This is a call-site binding problem — the classic inline-cache shape — not a
cache-lookup, fusion, manifest, or validation problem, each of which was
hypothesised and refuted earlier in this document.

### The fix, and its bound

Bind those 74,726 edges once each and ~99.95% of 136 M gateway round-trips
disappear. The source block is PRIVATE and therefore writable (`MAP_JIT`), so its
gateway-exit stub can be rewritten in place to reach the shared target directly —
subject to branch range, since a loaded unit is a separately mapped image and may
sit outside a `b`'s +/-128 MiB, in which case the stub needs an indirect hop
through a writable slot rather than a direct branch.

## Run 12 — A1 design: every unknown resolved by measurement

### Branch range: reachable, measured

A private -> shared patch needs the target within a `b`'s +/-128 MiB. Publishing
each loaded unit's executable range through `dsr-cache-bounds` and measuring the
distance to that process's private cache, over one go-build:

| | distance, private cache <-> loaded unit |
|---|---|
| min | 0.0 MiB |
| median | **1.4 MiB** |
| max | **2.0 MiB** |
| within +/-128 MiB | **53 / 53** |

A direct `b` reaches in every observed case. No indirect hop is required — though
the patcher must still range-check and fail closed to the existing gateway exit,
because nothing guarantees this placement.

(That probe call also fixes a real gap in
`scripts/dtrace/native-jit-aware-profile.d`: it knew only the private cache, so
shared-unit samples were being filed as host code.)

### The patch point already exists in private blocks

`assemble_block_inner` records a `DirectLink { slot, source, target, kind, stub }`
for every direct exit **regardless of `DirectExitEmissionPolicy`**, and emits at
`slot` the word `0x1400_0001` — `b` to the next instruction, which simply falls
into the gateway-exit stub. Rewriting that ONE word to `b <target>` makes the
edge jump straight to the target and never reach the gateway. This is exactly
what `patch_same_unit_direct_link` already does for intra-unit edges at pack
time; private blocks carry the same patch point, unused at runtime.

Private blocks are `MAP_JIT` and therefore writable, so the rewrite is legal
where a shared unit's `VM_PROT_READ|VM_PROT_EXECUTE` pinning made one impossible.

### What is missing, precisely

`PublishedBlock` retains `entry`, `len`, `map`, `recovery`, `_generation` — **not
`direct_links`**. The resolver therefore cannot find the slot for the
`(source, target)` it just resolved. Retaining them (or a side index
`(source, target) -> slot cache VA`) is the one structural addition the fix
needs.

The other half is invalidation, and it must not be improvised: a patched slot
points at a target whose generation can advance. `DirectBindingTable::invalidate_target`
already does this for unit CELLS, keyed by `(page, generation)`, and
`ProcessState::translate` already walks `dependencies.invalidate_page` on every
generation bump. A private slot patch has to be registered in the same structure
so the same walk restores it to `0x1400_0001`.

### Expected effect

74,726 edges bound once each against 136 M traversals: ~99.95% of the
private -> shared round-trips disappear, which is 99.4% of all resolver exits in
the sharing-ON arm. That is the whole of gate A1, and it is what makes A2's
translation-reuse win (1,046,467 -> target 400,000 translations) collectable
rather than swamped.

## Run 13 — the A1 one-line fix is REFUTED by a live experiment

Run 12 found the exclusion that produces the whole amplification, in
`ProcessState::publish_emitted`:

```rust
if let Some(target) = self.blocks.get(&target_key)
    && !self.shared_blocks.contains_key(&target_key)   // <- shared targets refused
{
    let word = encode_aarch64_direct_branch(site, *target)?;
    self.cache.patch_code_word(site, word)?;
} else {
    self.pending.entry(target_key).or_default().push(site);
}
```

Every private -> shared call edge takes the `else`, is queued in `pending`, and —
because the shared-unit load path inserts into `blocks` without draining
`pending` — is never patched. It re-resolves through the gateway forever.

Removing the exclusion and draining `pending` at unit load **crashes the guest
immediately**:

```
Error: unsupported in this backend: native DSR fault lies outside
guest-owned host memory: 0x20; recovered_guest_pc=0x97ed0
shared_unit_hits=1 shared_blocks_mapped=3706
```

### Why, and what it means

A fault at `0x20` is a null dereference at a small offset. A loaded unit's block
reads **unit-specific state from the `DsrContext`** — its `generation_bindings`
table (`ldr x19, [x28, #CTX_GENERATION_BINDINGS]`, then
`ldp x19, x17, [x19, #index*16]`), plus the unit's cache range and target
authority. The gateway installs that state when it enters a unit
(`enter_translated_with_cache_range_and_generation_bindings_and_catalog`); the
private context carries `generation_bindings: std::ptr::null()`. A direct branch
bypasses the installation, so the shared block's own generation guard
dereferences NULL and faults.

**The exclusion is load-bearing, not an oversight.** Reverted, and the guest is
BUILD_OK again. The condition now carries this reason in a comment so it is not
removed a second time.

### What the real fix has to do

A private -> shared edge cannot be a bare `b`; it must first install the target
unit's context state. Two shapes, both bounded:

1. **Per-edge trampoline.** Each `DirectLink` already reserves a 256-byte stub
   envelope. Patch the slot to branch into a trampoline that stores the unit's
   `generation_bindings`, cache range and authority into the context, then
   branches to the target. ~74,726 edges x a few words is on the order of 1-2 MB
   of extra emitted code — which lands in Workstream B's budget, so the two
   interact and must be measured together.
2. **Make the state not per-unit.** One process-wide binding table and executable
   range covering private code and every loaded unit removes the switch
   entirely, so a bare `b` becomes correct. Larger change, no per-edge cost, and
   it also deletes the gateway's per-entry installation work.

Shape 2 is the better end state and shape 1 is the cheaper probe of whether the
win is real. Either way the earlier estimate stands: binding these 74,726 edges
removes ~99.95% of 136 M gateway round-trips.

### Kept from the failed attempt

`patch_direct_link_if_reachable` replaces a hard error with a graceful fallback
when a target is outside `B` range: the unpatched site still holds its
`b`-to-next-instruction into the gateway stub, which is correct and merely
slower. Turning a placement accident into a failed translation was never right.

### Run 13b — both proposed shapes are wrong, and a third is not

Following the run 13 crash through, the two shapes proposed there do not survive
contact:

**Shape 1 (per-edge trampoline) is unsound.** A trampoline can install the
unit's context state on the way in, but a direct branch has no return point, so
nothing restores it on the way out. Control leaving shared code would run private
blocks with a unit's state installed, and the signal handler classifies faulting
PCs against exactly that state. A one-way branch cannot switch a *mode*.

**Shape 2 (one unified binding table) is not constructible.** A unit's binding
INDICES are baked into its immutable code at pack time and are unit-relative. A
process loading several units cannot give them a common base without rewriting
those indices, and it cannot rewrite them: unit code is pinned
`VM_PROT_READ|VM_PROT_EXECUTE` (`LoadedTranslationProtection::ImmutableCode`) and
is shared across processes.

**Shape 3, which does survive.** Only ONE context field is genuinely per-unit:
`generation_bindings`. The others are not —

* the executable-range **catalog** already holds many ranges
  (`executable_ranges.prepend(cache_start, cache_end)`), and the signal handler
  already accepts "inside `cache_start..cache_end` OR in the catalog";
* private blocks guard with `GenerationGuard::Absolute` (a baked cell address)
  and never read `generation_bindings` at all — `BindingIndex` is constructed
  only in a test.

So if a process's `generation_bindings` pointer can be installed ONCE and left
alone, a private -> shared direct branch needs no switch and becomes safe. The
measurement says that is the common case already: **53 loaded units across 70
processes**, i.e. most processes load at most one unit.

Concretely: install the unit's `generation_bindings` at LOAD time rather than per
gateway entry, permit the direct-link patch while a process holds exactly one
loaded unit, and fall back to the gateway exit (today's behaviour) the moment a
second unit loads. That is a far smaller change than either earlier shape, it
preserves the existing path as the fallback, and it is gated by a condition the
process can check locally.

The falsification clause in the goal is therefore NOT triggered: the
amplification is not intrinsic to sharing loaded units, it is intrinsic to
sharing MORE THAN ONE of them per process — and the workload almost never does.

## Run 14 — shape 3 also refuted; stop inferring the context contract, measure it

Shape 3 was implemented as specified: `sole_unit_bindings()` returns the one
loaded unit's table when a process holds exactly one, `PreparedEntry` installs
that table on EVERY entry (private included) so the context no longer depends on
which block the gateway entered, and the private -> shared patch plus the
unit-load `pending` drain were gated on that condition.

It still crashes — and the fault MOVED:

| attempt | fault address |
|---|---|
| run 13 (no context work) | `0x20` |
| run 14 (uniform `generation_bindings`) | **`0x60`** |

A moving fault address is informative: installing the binding table fixed the
first missing field and exposed a second. So `generation_bindings` is necessary
but NOT sufficient — entering a shared block requires at least one further piece
of per-unit context, and reading the code did not enumerate it correctly twice
in a row.

Reverted; the guest is BUILD_OK again and the tree is clean at `1dcc3d1a`.

### The method correction

Three attempts (runs 13, 14) have now inferred the context contract from source
inspection and been refuted by a live crash costing a full build-and-run each.
The contract must be MEASURED, not read:

**Diff the `DsrContext` across a shared entry and a private entry.** Both go
through `prepare_entry` -> the gateway; capture the full context struct at each
and compare field by field. Every field that differs is a piece of per-unit state
a direct branch would have to preserve, and the diff enumerates them exhaustively
in one run instead of one-per-crash. `0x20` and `0x60` are the offsets already
implicated; the diff will say what lives there and what else does.

Only once that set is known can the choice be made honestly between "install all
of it uniformly under the sole-unit condition" and "accept the gateway round-trip
and make it cheap" — the latter being the fallback the goal's falsification
clause anticipates, since the exit itself may be irreducible while its ~1,822x
per-edge repetition is not.

## Run 15 — what the crash actually says, and the corrected A1 target

Two facts narrow it much further than "some context field is missing".

**1. The context fields a unit's code reads are all common, not per-unit.**
Disassembling a published 3.7 MB unit and extracting every `x28`-relative access
gives, by frequency: `0x460`, `0x438`, `0x488`, `0x3a8` (NZCV save), `0x4b0`
(biased fault address), `0x4a8` (**`host_bias`**), `0x490`, `0x448`, `0x88`
(guest x17 slot), `0x440`, `0x4f0` (**`generation_bindings`**), `0x430`
(`CTX_ENTRY`), … Only `0x4f0` is per-unit, and shape 3 already installed it.

**2. The fault is a HOST address that cannot be lowered, not a bad context
read.** The message comes from `lower_dsr_fault_address`: a biased memory access
produced host address `0x60` and `guest_fault_address()` refused it. A biased
access computes `guest | bias`, so `0x60` means the guest BASE REGISTER held
~zero when the access executed — the block ran with wrong register state, not
with a wrong context.

### So the missing piece is a register/slot convention, not context state

A `DirectLink`'s `slot` sits BEFORE its exit stub: the slot holds
`b`-to-next-instruction and falls into the stub, which saves guest registers
(guest x17 to context slot `0x88` among them) before entering the gateway.
Patching the SLOT therefore skips the stub's saves, and the target block's
prologue — which reloads guest x17 from slot `0x88` — reads whatever was left
there by some earlier exit.

That is consistent with both crashes and with private -> private patching being
safe today only because those targets are reached under the same convention the
private emitter maintains end to end.

### The corrected A1 target

Do not patch the slot. The binding has to preserve whatever the stub establishes,
which means either patching the stub's FINAL branch (after its saves) rather than
its entry, or emitting a dedicated bind-target stub that performs the saves and
then branches. `emit_cached_direct_exit` — the `PortableUnitAuthority` path —
already has exactly this shape, which is why unit-internal edges bind safely and
this attempt did not.

This is now a specific, checkable statement rather than a hypothesis about
missing context: compare what `emit_gateway_exit`'s stub writes before entering
the gateway against what a target block's prologue reads, and patch at a point
after every one of those writes.

## Run 16 — the primary metric, measured; and the instrument is 4x better than assumed

Tip `e83957a1` against baseline `0686248a`, 8 quads, ABBA-ordered, both arms
separately built and signed:

| metric | median ratio | wins | p | sd | resolvable |
|---|---|---|---|---|---|
| wall | 0.9954 | 6/8 | 0.1445 | 1.46% | ≥0.85% |
| **CPU-seconds** | **0.9947** | 7/8 | 0.0352 | **1.28%** | **≥0.74%** |

**Primary metric: 0.9947 against a target of ≤0.70. Not met**, and expected not
to be: everything between those two commits is diagnostics. The block cache and
the hardware SHA-256 backend both landed BEFORE the baseline, so this pair
deliberately contains no performance change. The 0.53% is at the resolution
limit and should be read as "indistinguishable from no change", which is what was
predicted before running it.

### The result that matters is the sd

| protocol | metric | sd | smallest resolvable effect |
|---|---|---|---|
| plain A-then-B, 10 pairs | wall | 5.05–5.54% | ≥2.6–3.2% |
| **ABBA, 8 quads** | **CPU-seconds** | **1.28%** | **≥0.74%** |

The instrument is roughly **four times more sensitive** than the one every
earlier conclusion in this document was drawn with. Two changes did that: CPU
seconds instead of wall (`7c701293`), and ABBA ordering, which cancels the ~1%
second-position penalty a null screen measured on identical binaries.

### This invalidates the goal's out-of-scope clause

The goal excludes codegen cycle quality on the grounds that three attempts each
measured ≤2.6%. But ≤2.6% was the RESOLUTION FLOOR of the instrument used, not a
measurement of the effect — those screens could not have distinguished a real 2%
win from zero. At ≥0.74% resolution:

| change | measured then | status now |
|---|---|---|
| whole generation-guard check removed | median 0.9867, p=0.38 | 1.3% is now well above the floor — re-measurable |
| exit-target literal pool | "inconclusive", ~2% | ~2% is now ~3 sd — re-measurable |
| gateway phase claim | median 1.0030, p=0.62 | genuinely ~0, stands |

Two of the three were never actually refuted; they were unmeasurable. They
should be re-screened under ABBA+CPU before staying out of scope — the literal
pool especially, since it is also a Workstream B item (−41 MB emitted) and now
has two independent reasons to land.

**Method note for the campaign: re-measure a rejected change whenever the
instrument improves by more than the effect that rejected it.**

## Run 17 — the context explanation is dead; it is register state

Rather than attempt a fourth fix by inspection, the fault was made to report the
live `host_bias` alongside the unlowerable address, and the minimal repro (lift
the exclusion only) was run:

```
native DSR fault lies outside guest-owned host memory: 0x20
(host_bias=0x8000000000)
```

**`host_bias` is correct.** The context did not lose its address mode. And `0x20`
is five orders of magnitude below the bias, so the faulting access did not
compute `guest | bias` from a valid guest pointer — the guest BASE REGISTER held
~0x20 when it executed.

That closes the branch of the search this document has spent runs 13-15 on:

| explanation | status |
|---|---|
| missing per-unit context field (`generation_bindings`) | necessary but insufficient (run 14) |
| context lost its address mode / `host_bias` | **REFUTED — bias is correct** |
| wrong guest register state at the target's entry | **the surviving explanation** |

### What the next attempt needs, and it is not more reading

The surviving explanation is a register/slot convention, and identifying WHICH
register needs the faulting CACHE pc — the emitted instruction — not the guest
PC the error currently reports. The guest PC says which guest instruction was
being emulated; the cache PC says which emitted word ran and therefore which
lowering produced the bad base.

So the next step is: report `snapshot.pc` (the cache address) at the fault,
disassemble the emitted words around it from the code snapshot, and read the
base register out of the faulting instruction directly. That is one run and it
names the register, where three rounds of source inspection have named the wrong
thing three times.

Recorded as a hard rule for this problem: **do not propose another A1 fix without
the faulting cache PC and the decoded instruction in hand.**

## Run 18 — the faulting site is a CALL, and the obvious call hazard is excluded

Decoding the faulting guest instruction (reported at the fault by reading the
guest word and printing it) across every failure in one repro run:

```
9x  recovered_guest_pc=0x97ed0  insn=[94000ed4 …]
1x  recovered_guest_pc=0x7e880  insn=[94000ec4 …]
```

`0x94000ed4` is a **`BL`** — a call. So every failure is at a patched
private -> shared CALL edge, which is consistent with the A1 sizing: the 74,726
edges are call sites, and `SHARED -> private` (returns) barely appears because
returns are indirect.

The obvious call hazard is that a patched branch skips the link-register write.
It does not: `assemble_block_inner` emits

```rust
if exit.kind == DirectKind::Call {
    emit_mov_u64(.., 30, MaterializedValue::Guest(exit.resume.raw()), ..)?;   // x30
}
…
let slot = current_offset(&assembler)?;      // <- the patch point, AFTER x30
emit_word(.., 0x1400_0001)?;
```

so guest x30 is established BEFORE the slot and survives the patch.

### Running tally of excluded explanations

| candidate | status |
|---|---|
| missing per-unit context (`generation_bindings`) | necessary, insufficient (run 14) |
| context lost its address mode (`host_bias`) | refuted — bias is correct (run 17) |
| patched branch skips the link-register write | **refuted — x30 precedes the slot** |
| some other guest register the target's entry expects | surviving |

The fault is a guest base register holding ~0x20 on entry to the callee. Four
mechanisms have now been named and excluded by measurement, each costing a
build-and-run.

### Stopping rule for A1

The surviving explanation cannot be settled by more single-shot experiments: it
needs the callee's emitted prologue and the live register file at the fault,
i.e. a debugger session (`process save-core` + `bt all`, per AGENTS.md) or an
instrumented dump of the guest register file at the unlowerable-fault site.
Anything less is a fifth guess.

What is durable from this: the amplification is entirely private -> shared CALL
edges, they are bindable in principle (range measured, patch point identified,
link register verified safe), and four wrong explanations are written down so the
next attempt does not re-derive them.

### Run 18b — the kind bisect fails too; A1 is debugger work

Excluding `DirectLinkKind::Call` from the shared-target patch and leaving every
other kind patched **still faults at `0x20`**. So the failure is not
call-specific, and run 18's inference from "every reported guest PC is a `BL`"
was over-drawn: the reported PC is the exit SOURCE, and most edges into shared
code happen to be calls, so seeing only `BL` there says nothing about which
edges break.

That is the fifth mechanism named and killed by measurement:

| candidate | verdict |
|---|---|
| missing per-unit context (`generation_bindings`) | necessary, insufficient |
| context lost its address mode (`host_bias`) | refuted — bias correct |
| patch skips the link-register write | refuted — x30 precedes the slot |
| failure is specific to CALL edges | **refuted — excluding them still faults** |
| some other guest register the callee expects | surviving, unproven |

**A1 is now explicitly debugger work, not experiment work.** Five single-shot
experiments have each cost a build-and-run and returned a negative; the surviving
explanation needs the live register file and the callee's emitted prologue at the
moment of the fault. The next person should take a core
(`lldb -p <pid> -o "process save-core …"`, per AGENTS.md) or dump the guest
register file at the unlowerable-fault site, and read the answer rather than
proposing a sixth candidate.

Everything else needed is already established and recorded: the amplification is
entirely private -> shared edges (99.4%), it is 74,726 distinct edges at 1,822
traversals each, the branch range reaches (53/53 within +/-128 MiB), the patch
point exists and is writable, and the exclusion that blocks it is one line in
`ProcessState::publish_emitted`.

## Run 19 — a 9.3% emitted-size cut moves CPU by nothing, and that re-scopes Workstream B

`3d480e88` narrows gateway-exit guest-PC materialization. Mechanism gate passed
outright: emitted bytes **610,046,264 -> 553,300,180 (-9.3%)**, private direct
stub 56 -> 32 bytes, copy-only block 56 -> 44 bytes, both arms BUILD_OK with 71
guest processes each.

ABBA screen, 7 quads, `wide` vs `narrow`:

| metric | median ratio | wins | p | sd | resolvable |
|---|---|---|---|---|---|
| wall | 0.9919 | 5/7 | 0.227 | 2.05% | ≥1.28% |
| **CPU-seconds** | **1.0006** | 3/7 | 0.773 | 1.17% | ≥0.73% |

**No CPU effect**, on an instrument that resolves 0.73%.

### The arithmetic said so in advance, and it re-scopes the workstream

`memmove` + `memset` + `sys_icache_invalidate` total 2.7% of CPU. Cutting emitted
bytes by 9.3% can only move that by 9.3% x 2.7% = **0.25%** — a third of the
resolution floor. The result is exactly what the numbers predicted; running it
was worth doing to confirm the coupling, not to discover it.

Extrapolating honestly: hitting Workstream B's emitted-bytes target of 400 MB
(-33% from 599 MB) would move that term by 33% x 2.7% = **0.9%**, barely above
the floor — and would do essentially nothing for B's other target, host share
35.8% -> 25%. **The two B targets are not connected by enough leverage for one to
deliver the other.**

That means B's premise as written — "codegen enters scope as size reduction only,
because emitted bytes are what memmove/memset/icache scale with" — is true but
much smaller than it looks. The host bucket's 35.8% is not made of bytes moved;
it is made of the WORK of translating: `decode_spec`, `assemble_block_inner`,
`BTreeMap::insert`, malloc traffic, and the per-block metadata retained for
~1.2 M blocks.

### Where that leaves the goal

The host-side lever is the NUMBER of translations, not the size of each one —
which puts the weight back on Workstream A (cross-process reuse), and on making
per-block translation cheaper algorithmically rather than smaller.

The change is kept: it is strictly less emitted code, ~57 MB less JIT per build,
with no identified cost and no measured CPU change. It is NOT counted toward any
compounding total, and the campaign should stop expecting emitted-size work to
pay in CPU.

## Run 20 — the crash, finally diagnosed from the register file

Five mechanisms were proposed from source inspection and refuted. The snapshot
had the answer the whole time. Dumping it at the unlowerable fault:

```
esr=0x92000006  far=0x20
small_regs=[x3=0 x4=0 x5=0 x6=0 x8=0 … x19=0x0 x20=0 … x26=0]
```

- `esr = 0x92000006` — data abort, translation fault.
- `far = 0x20` — the hardware faulting address.
- **`x19 = 0`** — and x19 is `gateway::RESERVED_SCRATCH`, the register a
  `GenerationGuard::BindingIndex` guard loads the binding table into:

```asm
ldr x19, [x28, #CTX_GENERATION_BINDINGS]   ; x19 = table base
…
ldp x19, x17, [x19, #index*16]             ; faults here
```

With a NULL table base, `index = 2` gives `2 * 16 = 0x20` — **exactly the
observed FAR**. Run 14's shape-3 attempt faulted at `0x60`, which is
`index 6 * 16`: the same dereference at a different block's index.

So the crash is, and always was, **a shared block's generation guard indexing a
NULL `generation_bindings` table**. That is the mechanism run 13 named first and
run 14 tried to fix — the fix direction was right, and its *implementation* was
what failed: `sole_unit_bindings()` returned `None` for the entries that
faulted, so `PreparedEntry` still carried `generation_bindings: 0`.

### Why the earlier reasoning went wrong, and it is worth naming

Run 17 measured `host_bias` as correct and concluded "not a context defect, it is
register state". Both halves were true and the inference was still wrong: the bad
value *was* in a register (x19), and that register's contents came *from* the
context. A correct measurement of one context field does not clear the context.

The five refutations remain valid as refutations — they each excluded a specific
mechanism — but the search was ordered by what was easy to read rather than by
what the fault was already reporting. **The register file should have been the
first measurement, not the sixth.**

### The corrected fix

Shape 3's idea stands: with one loaded unit, install its `generation_bindings`
uniformly so the context does not depend on which block the gateway entered. Its
implementation must change in two ways:

1. Install the pointer **at unit load**, into process state that every
   `PreparedEntry` reads unconditionally — not via a per-call
   `sole_unit_bindings()` that returns `None` whenever the process is between
   states.
2. **Gate the patch on the pointer actually being installed**, not on unit
   count, so an edge can never be patched while the context could still carry a
   NULL table.

That is now a fix with a confirmed mechanism behind it rather than a sixth
guess.

## Run 21 — the fix WORKS: 135.7 M -> 0. One residual NULL-table path remains

With the run-20 diagnosis in hand (a shared block's guard indexing a NULL
`generation_bindings`), the corrected fix installs the unit's table at LOAD into
`ProcessState::installed_unit_bindings`, has every `PreparedEntry` -- private
entries included -- carry it, gates the shared-target patch on it being
installed, and records each patched site so a second unit's arrival restores them
(binding indices are per-unit, so a second unit's block would index the first
unit's table).

Measured on the sharing-ON arm:

| metric | before | with the fix |
|---|---|---|
| `resolve_src_private_tgt_shared` | 135,715,237 | **0** |
| `direct_resolver_exits` | 136,489,314 | **68,941** |
| gateway entries | 272,690,918 | **323,384** |

**The amplification is eliminated** — the exact population A0 identified as 99.4%
of all resolver exits goes to zero, and total direct-resolver exits fall by a
factor of ~1,980. That is the mechanism gate for A1, passed.

### What still fails

The run does not reach BUILD_OK: a residual fault at `far=0x60` — the same NULL
table at binding index 6. So one path still reaches a shared block with
`generation_bindings == 0`. Fork is NOT it: `after_fork_child` leaves
`installed_unit_bindings` intact, and `MAP_JIT` is `MAP_PRIVATE`, so a child
inherits both the patched code and the installed pointer.

The remaining suspect is install/patch ORDERING: a unit is loaded lazily by
`try_load_shared_unit` *during* a translate, i.e. inside a gateway entry whose
`PreparedEntry` was built before the load and therefore carries
`generation_bindings: 0`. Patches become live immediately. Any path that reaches
a patched branch without first re-entering the gateway would run with the stale
NULL context.

The fix for that is to gate patch-enable on the CURRENT entry already carrying
the table, rather than on the process having installed it — which needs the
thread's prepared-entry state threaded into `ProcessState::translate`, a
signature change through `translate_read_mostly`.

Reverted, because a crashing change cannot ship. But the approach is now proven
rather than hypothesised: it removes 135.7 M gateway round-trips, and what is
left is one ordering condition with a named fix.

### Run 21b — the ordering gate is not sufficient, and it has a threading defect

Gating the patch on the CURRENT entry carrying the table -- staged into
`ProcessState::current_entry_carries_bindings` under the same write guard as the
translate, set from `PreparedEntry::generation_binding_count` -- still faults,
now at `far=0`, i.e. the same NULL table at binding index 0.

Two things are wrong with that attempt, and the second is mine:

1. **The gate does not cover every path.** A patch armed during an entry that
   carried the table is still live for every later entry, so a NULL-table entry
   must still exist somewhere the gate does not see.
2. **The staging is per-PROCESS but the fact is per-THREAD.** Several guest
   threads share one `ProcessState`; thread B's `false` can overwrite thread A's
   `true` between A staging it and A's patch decision reading it. On a
   multi-threaded guest that is a race, not a gate — it needs to be a parameter
   on the call, not a field on shared state.

Reverted. Tree clean, tip BUILD_OK, 186 + 166 tests green.

**What stands from runs 20-21, and it is the substantive result:** the mechanism
is diagnosed (a shared block's guard indexing a NULL `generation_bindings`,
confirmed from the register file, `far == index * 16`), and installing the table
at load DOES eliminate the amplification — `resolve_src_private_tgt_shared`
135,715,237 -> 0 and `direct_resolver_exits` 136,489,314 -> 68,941, a ~1,980x
reduction. What is not yet solved is guaranteeing that EVERY entry reaching a
patched branch carries the table, on a multi-threaded guest, including entries
prepared before a lazy unit load.

The next attempt should thread the fact as a parameter through
`ProcessState::translate` rather than staging it on shared state, and should
enumerate the entry paths that can reach a patched branch instead of assuming
`prepare_entry` is the only one.

### Run 21c — thread-local gating: amplification gone again, NULL path survives

Third construction of the A1 fix, correcting run 21b's race by moving the patch
decision onto the thread that owns the fact:

* `installed_unit_bindings` set at unit LOAD, carried by every `PreparedEntry`
  including private ones;
* `ThreadTranslator::entry_carries_bindings` recorded in `prepare_entry` --
  per-thread, so no cross-thread overwrite;
* patching moved out of `publish_emitted` and into the `ResolveDirect` handler,
  where it runs only if THIS entry carried the table, draining `pending` for the
  resolved target;
* patched sites recorded so a second unit's arrival restores them.

Result: amplification eliminated again --
`resolve_src_private_tgt_shared` 135,715,237 -> **48**, `direct_resolver_exits`
136,489,314 -> **69,140**, gateway entries 272,690,918 -> **332,194** -- and the
run still faults at `far=0`, a NULL table at binding index 0.

Checked and excluded as the NULL source: `enter_prepared`'s
`enter_translated_with_trusted_private_cache` branch is guarded by
`!shared_translation_runtime_enabled()`, so it cannot be taken in this
configuration; the `generation_binding_count == 0` branch is unreachable once the
table is installed; and fork inherits both the patched code (`MAP_JIT` is
`MAP_PRIVATE`) and the installed pointer at the same virtual address.

**Three independent constructions, each eliminating 135.7 M gateway round-trips,
each leaving one entry path that reaches a shared block with a NULL table.** The
consistency of that outcome is itself the finding: the patch mechanism is right
and some entry path into translated code does not carry the prepared context.
Enumerating those paths — every route from host code into the cache, not just
`prepare_entry`/`enter_prepared` — is the remaining work, and it is enumeration
work, not another gate.

Reverted. Tree clean, tip BUILD_OK.

### Run 21d — the entry paths ARE enumerated, which refutes run 21c's own theory

Run 21c closed by proposing that some unenumerated route from host code into the
cache fails to carry the prepared context. Enumerating them settles it: on
aarch64 there are exactly **three** `gateway::enter_translated*` call sites
outside tests and the oracle, and all three are in `ThreadTranslator::enter_prepared`:

| branch | condition | carries bindings |
|---|---|---|
| `enter_translated_with_trusted_private_cache` | `count == 0 && !shared_translation_runtime_enabled()` | n/a — unreachable with sharing on |
| `enter_translated_with_cache_range_and_catalog` | `count == 0` | no |
| `..._with_cache_range_and_generation_bindings_and_catalog` | otherwise | yes |

(The fourth hit, `native_darwin/dsr/mod.rs:109`, is a test-support entry; the
`carrick_dsr_x86` ones are the other architecture.)

So there is no hidden entry path. Every entry goes through `enter_prepared`,
which means `generation_binding_count == 0` at the middle branch is the only way
to reach translated code without a table — and with the table installed that is
reachable only when `shared` is `Some(authority)` whose own
`generation_binding_count` is zero, i.e. a unit published with an empty binding
table.

That also weakens the inference behind runs 20-21c: `far` values of `0x20` and
`0x60` matched `index * 16` for indices 2 and 6 and were persuasive, but
`far = 0` matches index 0 *and* matches any other null dereference equally well.
The first two were evidence; the third is not, and it should not be read as
confirming the same mechanism.

**Remaining work, now genuinely narrow:** determine whether any loaded unit
carries `generation_binding_count == 0` while owning blocks whose guards index a
table, and re-run the fault with the register dump restored so `far = 0` is
attributed rather than assumed. Both are single runs.

### Run 21e — fourth construction, and a process failure worth recording

A fourth construction added a safe point: `ProcessTranslator::entries_without_bindings`,
an atomic count of threads inside a gateway entry whose context carries no
binding table, incremented/decremented around `enter_prepared`, with the patch
allowed only when this thread carries the table AND that count reads zero. The
reasoning was that a unit loads lazily, so another thread could be mid-entry with
a NULL table and take a freshly armed branch — and once installed, no NEW entry
can lack the table, so a zero reading is durable.

Same outcome as the previous three: amplification eliminated
(`resolve_src_private_tgt_shared` 135,715,237 -> **44**, `direct_resolver_exits`
136,489,314 -> **53,045**), still faulting at `far=0`.

**The process failure.** Run 21d explicitly recorded: `far = 0` matches binding
index 0 but equally matches any other null dereference, so it must be attributed
before being acted on — and stated the next step as re-running with the register
dump restored. Two further fixes were then attempted WITHOUT doing that. Both
"fixed" a cause that had not been shown to be the current one.

So the honest position is not "the fourth gate failed"; it is that the last three
attempts were aimed at an unverified target. The measured facts remain:

* the amplification is 74,726 private -> shared call edges at ~1,822 traversals
  each, and patching them removes it — reproduced four times;
* the ORIGINAL faults at `far=0x20` and `far=0x60` matched `index * 16` for
  indices 2 and 6, which is real evidence for the NULL-binding-table mechanism;
* the CURRENT fault at `far=0` is unattributed.

**Do not write a fifth construction.** Restore the register dump from run 20
(`snapshot.x[]`, `esr`, `far` at the unlowerable-fault site), reproduce, and read
what `far = 0` actually is. Everything else about this fix is already known to
work.

## Run 22 — A1 attributed: the fault is not about the binding table

Run 21d said `far = 0` must be ATTRIBUTED before being acted on. Two fixes were
then attempted without doing that. This run does it.

Restored the full register dump at the unlowerable-fault site and re-applied the
minimal repro (private->shared edges patchable once a unit's bindings are
installed). Result: the amplification dies as it always does --
`resolve_src_private_tgt_shared` 135,715,237 -> **0**, `direct_resolver_exits`
136,489,314 -> **1,402** -- and the guest faults 11 times, all at
`far=0x60`, `esr=0x92000006` (translation fault, level 2), across two guest PCs.

`0x60 = 6 x 16`, which matches a `GenerationGuard::BindingIndex` dereference of a
NULL table at index 6. But the guard emits

    ldr x19, [x28, #CTX_GENERATION_BINDINGS]
    mov x17, #index
    add x19, x19, x17, LSL #4
    ldp x19, x17, [x19]          // faults here when the table is NULL

so a fault in that `ldp` implies `x19 = 0x60` and `x17 = 6`. The snapshot reports
`x19 = 0` and `x17 = 0` -- both are DSR-reserved scratch and not carried as guest
state, so the register file neither confirms nor refutes the guard. **`far = 0x60`
on its own remains non-diagnostic**, exactly as run 21d warned.

What settles it is not the registers. It is the comment already sitting on the
excluded branch, written at run 13 and then narrowed by me into "the bindings
pointer":

> A loaded unit's block reads unit-specific state from the context -- its
> `generation_bindings` table, **cache range and target authority** -- which only
> the gateway installs when it enters that unit.

A direct branch bypasses the gateway, so it bypasses **all three** installations.
Every one of the four constructions supplied exactly one of them. That is why each
one killed the amplification and still faulted, and why the fault kept moving
between `0x20`, `0x60` and `0` -- those are different unit-specific reads failing,
not one bug relocating.

### Consequence for Workstream A

The shape "let a private context branch directly into a shared block, and hand it
the missing state" cannot work by adding fields, because a private context may
reach blocks from ANY loaded unit while a context can hold one unit's authority at
a time. The two shapes that remain:

1. Make shared blocks reachable from private contexts guard with `Absolute`
   (self-contained, no unit-specific context read) -- costs the per-unit
   indirection that `BindingIndex` exists to provide.
2. Keep the exclusion and attack the 74,726 x 1,822 traversals by making the
   gateway exit cheap, rather than by removing it.

Neither is a variant of what was tried. A1 stays open, but it is no longer
mis-specified: the target is unit-authority installation, not a null pointer.

**A1 remains NOT MET. Primary metric unmoved at 0.9947 (target <=0.70).**
