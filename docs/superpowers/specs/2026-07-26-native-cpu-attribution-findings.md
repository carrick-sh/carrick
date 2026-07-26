# Where carrick's CPU actually goes on a real workload (native lane, 2026-07-26)

Attribution of `go build` of a hello-world with a cold `GOCACHE`, on the shipped
default backend (`--exec-backend native`, Darwin/aarch64). This is the
conformance suite's `go-build` case, so the numbers are directly comparable to
the gate.

**Headline: the guest program's own execution is not the problem, and neither is
the instruction decoder. 76% of all gateway exits are a single instruction
class — exclusive load/store (`LDXR`/`STXR`) — and the machinery that services
them, plus the re-translation their block-splitting causes, accounts for the
bulk of a 40x CPU gap against Docker.**

## The gap

| | wall | CPU |
|---|---|---|
| Docker (native arm64, same image, same command) | 0.94 s | **2.26 CPU-s** |
| carrick native lane | ~32 s | **~89 CPU-s** |

~34x wall, **~40x CPU**. Carrick is compute-bound, not latency-bound — an
earlier conclusion in the other direction was measurement error (see below).

Two independent measurements of carrick's CPU agree, which is why the number is
trustworthy: DTrace `profile-997` sampling put user CPU at **89.9 thread-seconds**;
the in-process NATIVEPERF v2 counters put `thread_cpu_ns` at **88.7**. Different
mechanisms, 1.4% apart.

## Process shape

`go build` of ONE file runs **65 guest processes**: 27 `compile`, 34 `asm`,
2 `link`, the `go` driver, and the built binary. Docker runs the same 65.

| image | n | summed lifetime | max |
|---|---|---|---|
| `compile` | 27 | 45.8 s | 16.8 s |
| `asm` | 34 | 10.1 s | 0.47 s |
| `link` | 2 | 0.74 s | — |
| built binary | 1 | 0.085 s | — |

A hello-world Go binary that prints one line costs **85 ms**, essentially all
startup tax.

## Where the CPU goes

From the in-process phase counters (88.7 CPU-s total; phases overlap where
translation nests, so these do not sum to 100%):

| phase | CPU | share |
|---|---|---|
| `phase_translate_ns` | 31.6 s | 36% |
| `phase_translated_run_ns` | 25.5 s | 29% |
| `phase_prepare_index_ns` (cache lookup per gateway entry) | 11.4 s | 13% |
| `phase_sensitive_emulation_ns` | 10.4 s | 12% |
| `phase_finish_exit_ns` | 8.9 s | 10% |
| `phase_syscall_dispatch_ns` | 4.4 s | 5% |
| `phase_loop_quiesce_ns` | 2.0 s | 2% |

Gateway machinery — `prepare_index` + `sensitive_emulation` + `finish_exit` —
is **30.7 s (35%)**. Translation is **31.6 s (36%)**. Actually running the
guest's translated code is only 29%.

Sampling agrees on the shape: 27% of samples in carrick's own text, 19% in
system dylibs (`memmove`/`memset`/`malloc` — largely translation's emit and
publish path), 54% in JIT/anon ranges.

## The cause: exclusive load/store

**38,898,088 gateway exits** for one hello-world build:

| exit kind | count | share of exits |
|---|---|---|
| `exit_sensitive` | 29,589,823 | **76.1%** |
| `exit_resolve_indirect` | 7,777,298 | 20.0% |
| `exit_resolve_direct` | 1,415,475 | 3.6% |
| `exit_syscall` | 112,703 | 0.3% |

And the sensitive exits are one thing, not a mix:

| sensitive kind | count | share |
|---|---|---|
| `sensitive_exclusive` | 29,589,283 | **100.0%** |
| `sensitive_read_tpidr` | 264 | 0.0% |
| `sensitive_dc_zva` | 205 | 0.0% |
| `sensitive_read_dczid` | 70 | 0.0% |

Go's runtime uses atomics on every mutex, channel operation, scheduler
transition, and GC write barrier. Each one is a full gateway round-trip: save
guest state, return to carrick, emulate one instruction, re-enter.

This is self-reinforcing, and that is why it costs more than the 10.4 s of
emulation alone:

1. A block must END at each exclusive, so blocks are tiny.
2. Tiny blocks mean **1.56M translated blocks** emitting **717 MB** of code —
   **460 bytes emitted per block**, against a typical 24–40-byte aarch64 basic
   block. Most emitted bytes are glue, not translated instructions.
3. Every block execution pays a cache-index lookup (11.4 s) and an exit
   reconciliation (8.9 s). There are 38.9M of them, ~25 executions per
   translated block.
4. 717 MB of emitted code against a few MB of native hot text is also an
   i-cache/iTLB working-set problem independent of instruction quality. NOT yet
   measured — needs Instruments/`kperf` PMCs, which DTrace cannot read.

## Secondary: capsule work repeated per process

~18% of all CPU is carrick re-running container/capsule setup on each of the 65
guest process execs, because guest processes self-reexec the carrick binary:

| work | share of all CPU |
|---|---|
| serde JSON ser/de | 8.2% |
| SHA-256 hashing (executable digest per exec) | 3.9% |
| capsule resources / volume mountpoints | 2.4% |
| string formatting | 2.3% |
| clap argument parsing | 1.2% |
| registry / auth (incl. JWT deserialize) | 0.3% |

Docker does none of this per process. Real and fixable, but a minority.

## What this says about the AOT cache

The file-backed AOT cache was scoped as a fork/memory optimisation and measured
at **−512 µs per fork**. As a *CPU* lever its case is now different from what was
assumed:

- Instruction DECODE is negligible: `decode2.c` + `decode_scratchpad.c` (bad64)
  together are **0.2%** of samples. An earlier reading that the decoder was the
  hot path was a symbolication artefact (below).
- But `phase_translate_ns` is **31.6 s (36%)**, and the same few binaries are
  translated from scratch 65 times. Caching translation across processes
  addresses that 36% directly.

So AOT remains well-motivated — but it attacks the *consequence*, and roughly
half the win would evaporate if exclusives stopped splitting blocks, because
there would be far less to translate. **Fix the exclusive trap first, then
re-measure translation before sizing AOT.**

## Ranked directions

1. **Run exclusive load/store natively instead of trapping.** Removes 76% of
   gateway exits, shrinks per-block glue, lengthens blocks, and cuts translation
   volume — the only single change that plausibly moves a 40x gap materially.
   Same-ISA aarch64-on-aarch64 with identity-mapped guest memory is the
   favourable case; the open question is why the exclusive monitor cannot be
   used directly today.
2. **Cut per-gateway-entry cost.** 11.4 s of cache-index lookup across 38.9M
   entries is ~290 ns per entry. Even with (1), indirect resolves remain 20% of
   exits.
3. **Stop re-running capsule setup per guest process** (~18% of CPU): hash-once
   executable digests, skip clap/serde re-parse on self-reexec.
4. **AOT translation cache** — re-size after (1).
5. **Measure i-cache/iTLB** with PMCs to size the working-set effect.

## Measurement notes — two traps, both hit here

**Do not time a hot path by bracketing its own probes.** Bracketing
`dsr-translate-begin`/`-end` fires ~3M USDT probes and each pair's cost lands
inside the window being timed; it reported 17.7 s of translation inside a 19 s
window. Sample instead (`scripts/dtrace/native-cpu-attribution.d`) and use the
cheap per-block probes only for exact COUNTS.

**Guest processes self-reexec, so every one has a different ASLR slide.**
Symbolicating a profile against one assumed base produces plausible, wrong
symbols — that is what made bad64's decoder look like the hot path. Each process
now announces its own image base (`host-image-base` / `guest-image-base` probes)
and `scripts/symbolicate.py` resolves per pid, against the host image and the
inner guest image separately.

Both traps share a shape: the measurement was capable of producing a confident
answer regardless of the truth. Prefer a method whose error mode is a visibly
missing number over one whose error mode is a plausible one.
