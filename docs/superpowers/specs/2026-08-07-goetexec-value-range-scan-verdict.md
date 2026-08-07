# Go ET_EXEC value-range scanning vs relocation ground truth: verdict

**Date:** 2026-08-07
**Question:** the relocation-route verdict
([`2026-08-07-goetexec-relocation-route.md`](2026-08-07-goetexec-relocation-route.md),
UNSOUND) left ~63% of absolute sites — packed `.rodata` — with no enumerating
metadata. The challenge: a relocator does not *need* metadata. Treat every
8-byte-aligned word in the metadata-free regions whose value falls inside the
image's PT_LOAD span `[image_base, image_end]` as an absolute pointer and add
delta, with the unmapped old range (`__PAGEZERO` below 4 GiB) as a SIGSEGV
safety net for anything missed. Does that close the gap?

**Verdict up front: UNSOUND — and now measured, not argued.** Against exact
two-base ground truth on seven real binaries, the scan has **perfect recall
(0 false negatives on every binary)** but **thousands of false positives on
every real toolchain binary — 9,150 on `cmd/compile`, 6,692 on `go`** — and
they are precisely the irreducible integer-table kind the risk table
predicted: the compiler's own `ssa.opcodeTable` (935), assembler opcode
tables, `strconv.uint64pow10`, `math/big.pow5tab`, type-descriptor
`Size_`/`PtrBytes`/`NameOff` scalars. Every false positive is a **silent
forward corruption**: the SIGSEGV net catches *stale low pointers* (misses),
never *integers turned into high garbage* (wrong fixups), so the net is
orthogonal to the failure mode. Both tested refinements (symbol-boundary
targets; aligned targets) trade a partial FP reduction for tens of thousands
of new misses. The prior UNSOUND verdict stands; **the micro-vmm remains the
only live route for the arm64 ET_EXEC canonical lane.**

---

## 1. Method and exact binaries

Static analysis only; no runtime changes, no guest runs. Probe:
[`scripts/perf/goetexec_valuescan.py`](../../../scripts/perf/goetexec_valuescan.py)
(kept; imports the census module's ELF/GC-program machinery rather than
re-implementing it). Receipts: `target/perf/goetexec-valuescan/*.json`,
`sigsegv-net-probe.txt`.

- **Ground truth** per binary: the two-base link diff
  (`goetexec_reloc_census.word_diff`) — the same program linked at text base
  `0x11000` and `0x100011000` (`GOTOOLCHAIN=go1.24.13`, `GOOS=linux
  GOARCH=arm64 CGO_ENABLED=0 GOFLAGS=-trimpath`,
  `-ldflags=-T=0x100011000`), a word differing by exactly delta IS an
  absolute site. Pairs measured: the `hello` fixture plus **six real
  toolchain programs built from the pinned toolchain's own source:
  `cmd/compile`, `cmd/go`, `cmd/link`, `cmd/asm`, `cmd/vet`, `cmd/cgo`**.
- **Transfer to the unmodified image binaries is checked, not assumed**: the
  scan profile of the conformance image's own go1.24.13 binaries
  (`go` `aedb1694ac1516bb…`, `pkg/tool/linux_arm64/compile`
  `5d3ce715273cf3be…`, `link` `3d8da962f016004e…`, already extracted from
  `localhost:5005/carrick-go-conformance:1.24`; no Docker run needed) matches
  the rebuilt twins within build-ID-sized deltas — compile `.rodata` hits
  63,842 vs 63,837, `.noptrdata`/`.data` identical
  (`image-transfer.json`).
- **Scan domain** (what a metadata-augmented relocator would value-scan): all
  8-aligned words of `.rodata` and `.noptrdata`, plus the `.data` words the
  `gcdatamask` does NOT cover. Everything else is metadata-enumerable and
  verified complete on all seven binaries: `gcdatamask` (27,275 on compile) +
  `.itablink` (443) + `go:fipsinfo` (9) + `pcHeader.textStart` (1) account
  for **every** ground-truth site outside the domain — zero leftovers.
- **Image span** from the PT_LOAD headers (compile: `[0x10000, 0x121b1a8]`,
  three loads, base = min vaddr, end = max vaddr+memsz). Hit rule:
  `image_base <= value <= image_end`.

## 2. Results: recall is perfect, precision is fatal

| binary | in-domain GT sites | true pos | **false pos** | false neg |
|---|---:|---:|---:|---:|
| `cmd/compile` | 57,009 | 57,009 | **9,150** | **0** |
| `go` | 49,559 | 49,559 | **6,692** | 0 |
| `cmd/vet` | 44,697 | 44,697 | **1,771** | 0 |
| `cmd/link` | 21,550 | 21,550 | **1,136** | 0 |
| `cmd/asm` | 15,303 | 15,303 | **800** | 0 |
| `cmd/cgo` | 16,973 | 16,973 | **314** | 0 |
| `hello` | 5,775 | 5,775 | 84 | 0 |

- **FN = 0 everywhere**: every base-dependent word's value lies inside the
  PT_LOAD span (the prior census's 8 "outside-image" values fall in
  inter-section gaps the span covers). The scan never misses; the SIGSEGV
  net would never even be exercised.
- **FP is the kill**: on the canonical lane's own compiler, 9,150 words —
  13.8% of everything flagged in the domain — would get +delta added to a
  value that is **not an address**. In `.data`'s bitmap gaps the ratio is
  worst: 1,479 FPs against 134 genuine sites (11 corruptions per real fix).
- `.text` produces zero hits even raw-scanned (nothing to catch, as ground
  truth already said). Raw-scanning `.gopclntab` (outside the domain) would
  add 4,487 more FPs — its offset tables look exactly like small pointers.

## 3. What the false positives are (compile, all 9,150 classified)

| class | count | what the datum is |
|---|---:|---|
| type-descriptor scalars in `.rodata` types-region | 7,226 | `Str`/`PtrToThis` int32 pairs read as one word (2,739 — a `NameOff ≥ 0x10000` with `PtrToThis == 0` *is* an in-range u64); `Size_` slots of ≥64 KiB types (687); `PtrBytes` slots (1,014); other scalar fields — array/chan `Len`, struct-field offsets, method int32 pairs (2,786) |
| integer tables in `.data` bitmap gaps | 1,479 | `cmd/compile/internal/ssa.opcodeTable` **935**, `cmd/internal/obj/x86.optab` 309 + `avxOptab` 110, `riscv.instructions` 70, `<no-symbol>` packed data 49, `strconv.uint64pow10` 3 (10⁵–10⁷!), `types.typedefs` 3 |
| `.noptrdata` | 445 | anonymous packed integers (423), `math/big.pow5tab` (5⁷–5¹⁰), `runtime.firstmoduledata` slice **len/cap** fields (6 — e.g. `pclntable` len `0xd9b78` sits between two true pointers), `MemProfileRate`, unicode tables |

These confirm the challenged document's own risk table: **a compiler is made
of integer tables whose entries land in `[0x10000, ~19M]`**. Corrupting
`uint64pow10` breaks every strconv conversion; corrupting `opcodeTable`
mis-selects instructions; corrupting a moduledata slice len detonates the
runtime — all **silent**, none faulting at the corrupted-word's address.

## 4. Refinements tested — both trade FPs for catastrophically many FNs

| filter | FPs remaining (compile) | new FNs (compile) |
|---|---:|---:|
| value must equal an ELF symbol address or section start | 92 (not even 0 — 83 type-scalars coincide with symbol VAs) | **+47,743** |
| value must itself be 8-aligned | 3,578 | **+19,059** (33.4% of true pointers target byte-aligned data — `abi.Name` bytes, string bytes, gcdata bytes) |

True Go rodata pointers overwhelmingly point *into unnamed packed blobs* —
the same mid-object shapes the integers fake. There is no value-shape or
target-shape separator; telling `opcodeTable[i].auxint == 0x186a0` from a
pointer to VA `0x186a0` requires knowing the word's **type**, which is the
complete type-graph walk the prior verdict already showed cannot be built or
verified from an unmodified binary. The two verdicts compose: metadata can't
enumerate the sites, and values can't identify them.

## 5. The SIGSEGV-net premise: true, and irrelevant

Probe: [`scripts/perf/goetexec_pagezero_probe.c`](../../../scripts/perf/goetexec_pagezero_probe.c)
(receipt `target/perf/goetexec-valuescan/sigsegv-net-probe.txt`, Darwin
27.0.0 arm64):

- reads at `0x10000`, `0x117ac08`, `0x121b1a0` (the old image span) all
  raise **catchable SIGSEGV with exact `si_addr`** — a *missed* pointer that
  is ever dereferenced would be caught and fixable;
- `MAP_FIXED` anywhere in the old range fails `ENOMEM` — `__PAGEZERO` is
  reserved, the net cannot be mapped over; carrick's own binary carries
  `__PAGEZERO vmsize 0x100000000`, so the net exists in the Direct-mode
  host process;
- loader detail: old+4 GiB (`0x100010000`) collides with the host
  executable's own default `__TEXT` region — a relocating loader must pick a
  free delta (+8 GiB verified mappable). 16 KiB host pages make the *segment*
  base the mappable unit, as the direct tier already handles for 4K images.

But the net only catches **false negatives** — stale low values later
*dereferenced* (a stale value merely compared or used as a uintptr/map key
would stay silent). Measured FN = 0, so there is nothing for it to catch;
the actual failure mode, false positives, is corruption the relocator itself
*writes*, at addresses that are valid before and after. No fault, no net.

## 6. Verdict and consequences

**UNSOUND — confirmed against ground truth, closing the challenge.** The
false-positive set is nonzero on all seven binaries, dominated by exactly
the predicted integer-table class, irreducible without complete type
information, and every member is a silent corruption. This removes the last
hedge on the relocation route:

- The prior doc's verdict stands, now with the metadata-free variant also
  measured dead. Route C is closed from both directions.
- **The micro-vmm
  ([`../../perf-results/2026-08-07-microvmm-syscall-tax.md`](../../perf-results/2026-08-07-microvmm-syscall-tax.md))
  remains the only live route for the arm64 ET_EXEC canonical lane.** Its
  design spike stays unconditionally next; nothing here changes the PIE
  tier-D program.
- What would overturn this: nothing value-shaped. Only complete per-word
  type information (relocation records, i.e. PIE; or a user-controlled
  rebuild at a high `-T` base per the prior doc's guidance nugget) makes
  ET_EXEC direct execution sound.
