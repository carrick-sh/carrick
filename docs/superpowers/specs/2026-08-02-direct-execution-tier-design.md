# Direct execution: patch, don't translate

**Status:** design + de-risking spikes run (results below, all on this host,
macOS arm64, 2026-08-02). **Lane:** native backend (shipped default).
**Authorization:** "from first principles tackle the performance problem, we
are ok with needing to rearchitect things."

## 1. First principles

Carrick's native lane is **same-ISA**: aarch64 Linux guests on an aarch64
host. The guest's instructions are already correct for this CPU. Exactly three
things in a Linux binary cannot execute natively on Darwin:

1. **`svc #0`** — would enter XNU with Linux calling conventions; must reach
   carrick's dispatcher instead.
2. **x18** — Darwin's platform register; the kernel rewrites it at every trap
   return, so a guest value cannot live in the physical register.
3. **`mrs/msr tpidr_el0`** — guest TLS; viable natively only if XNU preserves
   the register per thread (it does not — probed below).

Everything else — every add, load, branch, SIMD op — could run unmodified.

The current architecture instead **translates every instruction** into a JIT
cache: a Rosetta-shaped design for a problem Rosetta does not have (Rosetta
must translate; the ISA differs). The measured consequences of that choice:

- 52.4% of executed emitted instructions are carrick's own glue
  (`native-dsr-shape-census.jsonl`), after seven codegen phases;
- 33.7% of emitted instructions are save/restore traffic for the four
  registers the translator steals (x15/x16/x17/x19) — and it also steals
  x28, which is Go's goroutine register, making every `g` access a memory
  round-trip;
- every exec retranslates its binary from scratch: ~129 ms per Go tool
  process vs Docker's ~1.05 ms, ~76% of a cold `go build`
  (`2026-08-02-exec-dominates-the-build.jsonl`);
- steady-state compute is ~5x Docker even for a long-running process
  (`2026-08-02-overhead-by-workload-shape.jsonl`).

Every same-ISA Linux-emulation system that shipped runs guest code **directly**
and intervenes only at the syscall boundary: FreeBSD's Linuxulator, illumos
lx-brand, WSL1. They are kernel-level; the question was whether userspace
Darwin allows the same shape. The spikes below answer it.

## 2. The static census: intervention is a 0.03% problem

`cargo run -p carrick-dsr-aarch64 --example insn_census` over binaries
extracted from the go-conformance image (committed as the example; numbers
from this host):

| file | insns | svc | x18 | tpidr | type |
|---|---|---|---|---|---|
| compile | 2,314,615 | 38 | 0 | 2 | EXEC 0x9b020 |
| asm | 495,166 | 37 | 1 | 2 | EXEC |
| link | 653,801 | 38 | 0 | 2 | EXEC |
| go | 1,444,460 | 37 | 3 | 2 | EXEC |
| rm | 13,046 | 0 | 14 | 0 | DYN |
| find | 46,336 | 0 | 97 | 0 | DYN |
| libc.so.6 | 349,448 | 513 | 683 | 1,485 | DYN |
| **total** | **5,316,872** | **663 (0.0125%)** | **798 (0.0150%)** | **1,493 (0.0281%)** | |

The entire Go toolchain — 4.9M instructions — needs ~150 svc patches, 4 x18
patches and 8 TLS patches. Even libc, the densest case, is 0.77% total. The
translator pays per-instruction overhead on 100% of the code to handle 0.03%
of it.

Caveat, fail-closed: bad64 leaves some words undecoded (2,166 in `rm`, 54,519
in libc — mostly literal pools and newer SIMD). An undecoded word executes
natively just fine; the risk is only a *missed* x18/tpidr access hiding in
one. The patcher must therefore treat undecodable words in executable regions
conservatively: a raw bit-pattern scan for register field 18 in the standard
operand positions over-approximates (false positives just add veneers), and
aarch64 ELF mapping symbols (`$x`/`$d`) identify literal pools when present.

## 3. The runtime probes: what Darwin allows

All probed on this host (scratchpad `lowva*.c`, `tpidr_probe.c`):

| probe | result |
|---|---|
| MAP_JIT + write-protect toggle + execute | **works** (as carrick's jit.rs already proves in production) |
| MAP_JIT with MAP_FIXED | **rejected** (mmap fails, any address) |
| `-pagezero_size 0x4000` main binary | **SIGKILL at exec** — kernel policy, no output ever |
| `mach_vm_deallocate` of a pagezero slice | returns KERN_SUCCESS but the range stays unmappable (mmap → MAP_FAILED, remap → KERN_INVALID_ADDRESS) |
| TPIDR_EL0 across syscalls/switches | **NOT preserved** — rewritten by the kernel at the first trap return (reads back small CPU-ish integers) |

Consequences:

- **Low guest VAs are hard-unreachable on arm64 macOS.** Confirms and
  strengthens the project's earlier finding: not linkable away, not
  deallocatable. Identity placement for low ET_EXEC (the Go toolchain at
  0x10000) is impossible in any Mach-O process.
- **PIE needs no fixed placement at all.** For ET_DYN, "identity" is whatever
  base we choose — so choose the address the MAP_JIT allocation returns. The
  MAP_FIXED rejection is irrelevant for PIE.
- **Guest TLS must be patched, not native.** `mrs xN, tpidr_el0` sites get a
  veneer reading the guest TLS value from a Darwin TSD slot (reachable via
  the EL0-readable TPIDRRO_EL0); `msr` sites write it. 1,485 sites in libc,
  8 in the whole Go toolchain.

## 4. The architecture: two tiers

**Tier D — direct execution** (new), for ET_DYN/PIE images and any ET_EXEC
whose segments sit above the pagezero floor:

- Load segments into a MAP_JIT region at a kernel-chosen base (PIE: this *is*
  the load bias). Copy text, then patch in place:
  - `svc #0` → `b island_i` (A64 instructions are uniformly 4 bytes; `b`
    reaches ±128 MB and the islands are allocated inside the same region).
    The island saves x30, `bl`s a common veneer that spills guest state and
    calls **the existing `SyscallDispatcher`** — the same entry the DSR
    gateway calls today. Syscall cost ≈ today's (~0.3 µs), no traps.
  - x18-touching instructions → per-site veneer against a memory slot
    (x18 is dead as a transfer register; the veneer owns it momentarily).
  - `tpidr_el0` accesses → TSD-slot veneer as above.
  - Bootstrap milestone may use `svc → brk #imm16` (single-instruction,
    trap-based, ~µs per syscall) before islands land; brk also remains the
    fallback for any site a veneer cannot reach.
- **No translation. No per-block anything.** Guest registers — including x28
  (Go's g), x17, x19 — live in their physical registers. Faults arrive with
  guest state in the real registers: the recovery-entry machinery, PC maps
  and generation guards do not exist in this tier.
- Guest-created executable pages (`mmap(PROT_EXEC)`, `mprotect(PROT_EXEC)`)
  are already intercepted syscalls: scan+patch at that boundary. RWX pages a
  guest writes without a protection flip (rare; JITs use W^X toggles) are the
  one shape this tier cannot hold — such a process falls back to tier T.

**Tier T — the existing DSR translator**, kept for:

- low ET_EXEC images (the Go toolchain) — the pagezero wall is physics;
- RWX self-modifying processes;
- diagnostics (the census/probe instrumentation rides on it).

This is not a compatibility shim (the tier split is by *image class*, decided
at exec, with one owner each) — but it must not become two drifting dispatch
paths either: both tiers call the same dispatcher, the same loader, the same
memory planner. The only difference is how guest code reaches syscalls.

## 5. What this is worth, honestly

- **cpython, node, dash/coreutils — the PIE world — go to ~1x compute.** The
  smoke's worst outliers today are node (22–23x) and cpython (14–17x); their
  guest code currently executes at 52.4% glue density plus per-process
  translation of every page they touch. Tier D removes both terms entirely.
- **Exec cost for PIE collapses**: copy text + one linear scan + patch ~700
  sites (libc) ≈ single-digit ms, vs ~129 ms translate-everything — and the
  patched image is trivially cacheable per executable (byte-identical check,
  no translator versioning).
- **Syscall-bound and fs-bound work is unchanged** — that is the dispatcher
  and VFS story (fs-walk is at 3.8x total-wall and has its own endgame doc).
- **Go stays on tier T** until its own levers land (container-lifetime exec
  cache, task #19; zygote). The build workload improves via those, not via
  tier D.
- The 2x bar: tier D makes it *reachable* for long-running PIE workloads
  (compute → ~1x; residual = syscalls + memory management). It does not by
  itself deliver 2x on `go build`.

## 6. Correctness constraints

- **Patch before first execution, never concurrently.** All patching happens
  with the region writable and no guest thread able to enter it (load time,
  or inside the intercepted mprotect/mmap before PROT_EXEC is granted), then
  one `sys_icache_invalidate`. No cross-modifying-code hazard exists.
- **Fail closed on undecodable executable words** (see census caveat): if the
  conservative scan cannot rule out x18/tpidr in a region, that image falls
  back to tier T with a named reason, counted in the census — never a silent
  best-effort.
- **Signals inside veneers/islands**: a handler needs guest-coherent state.
  Island ranges are known; delivery inside one defers (machinery exists —
  carrick already parks/redelivers). The veneer clobbers only x30-saved-first
  and the dead transfer register, so the interrupted frame is reconstructible
  by range, not by per-word recovery entries.
- **Guest reads of its own text see patched bytes.** `/proc/self/exe` and
  file reads see the original file (patches live in the private JIT copy).
  A checksum-self-via-memory guest would observe the difference; accepted and
  documented (the VMM lane is the refuge for such a guest, and none of the
  conformance corpus does this).
- **A guest is not a trust boundary** (AGENTS.md) — islands and slots live in
  guest-reachable memory, same as today's JIT cache.

## 7. Milestones

- **M0 (done, this doc):** census + Darwin probes. Decision evidence
  committed.
- **M1:** tier D for static-PIE + brk-trap syscalls, behind
  `CARRICK_NATIVE_DIRECT` during bring-up only. Prove: dash/coreutils run
  end-to-end; conformance smoke green with the flag on; measure one-process
  compute vs Docker (target ~1x, vs today's 5x).
- **M2:** dynamic linking (ld.so is just more PIE mappings through the same
  loader), tpidr/x18 veneers (libc needs them), syscall islands replacing
  brk. Prove: cpython + node smokes green on tier D; node/cpython outlier
  ratios collapse.
- **M3:** default ON for eligible images (opt-out hatch `=0` for bisection),
  tier decision logged + counted; exec-work cache for patched images.
  Delete what tier D obsoletes in the DSR-only path *for eligible images*
  (the no-dead-arms rule); tier T remains the owner of low-ET_EXEC and RWX.
- Throughout: the conformance gate is the ratchet — no tier flips a default
  until the full native smoke is green under it.

## 8. What this supersedes

The steady-state codegen campaign (compute 10.9x → 3.8x) attacked the glue
density *within* the translate-everything premise; tier D removes the premise
for the images that dominate the conformance corpus. Task #18 (per-site
slot-1128 attribution) is obsolete for tier-D images and remains relevant
only to tier T. The shared-translation store (fixed 2026-08-02, `9405aff5`)
remains the right shape for tier T and becomes the natural cache for patched
tier-D images.
