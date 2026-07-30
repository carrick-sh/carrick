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
