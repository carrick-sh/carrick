# Go ET_EXEC load-time relocation to a high VA: soundness verdict

**Date:** 2026-08-07
**Question:** can carrick's loader relocate an unmodified Go ET_EXEC
linux/arm64 binary above Darwin's 4 GiB `__PAGEZERO` floor — fixing up every
absolute reference the way a dynamic loader fixes a PIE — and run it directly
under tier D? If yes, it beats the micro-vmm on the canonical `go build` lane
(no per-syscall tax, translation and bias both gone). This was the ablation
ladder's Route C ([`2026-08-07-et-exec-direct-execution-options.md`](2026-08-07-et-exec-direct-execution-options.md) §4),
gated on one hypothesis:

> Go has a precise GC, so the runtime must know every pointer in data/bss
> (`gcdata`/`gcbss` reachable from `moduledata`). If the GC can enumerate every
> data/bss pointer to scan, a relocator can enumerate every pointer to fix.

**Verdict up front: UNSOUND.** The hypothesis conflates two different sets.
Go's GC metadata enumerates *heap-capable pointer slots*; relocation needs
*address-valued words*. Measured on the real Go compiler (the canonical lane's
own binary, ground truth from a two-link-base diff): **84,737 absolute-address
words; GC bitmaps cover 27,275 (32.2%); every known-layout mechanism combined
reaches ≈37%; ~53,400 sites (63%) have no enumerating metadata at all**, and
two classes are excluded from GC metadata *by design* (compiler-cited below).
One striking positive that does not save the route: **the text segment is
100% fixup-free** — zero absolute sites in `.text` on both fixtures, so no
disassembly would ever be needed. The route dies in `.rodata` and in the GC's
deliberate scalar-marking, not in code.

Consequence: **the micro-vmm
([`../../perf-results/2026-08-07-microvmm-syscall-tax.md`](../../perf-results/2026-08-07-microvmm-syscall-tax.md),
measured VIABLE) is the only live route for the arm64 ET_EXEC canonical
lane.** This relocation route would have dominated it where applicable; it
does not apply.

---

## 1. Scope and the exact binaries measured

- Static analysis only: no guest runs, no Docker, no runtime changes. Probe:
  [`scripts/perf/goetexec_reloc_census.py`](../../../scripts/perf/goetexec_reloc_census.py)
  (kept, per project probe policy). Receipts:
  `target/perf/goetexec-reloc/{hello,compile}-diff.json`.
- The canonical lane's image is `localhost:5005/carrick-go-conformance:1.24`,
  which ships **go1.24.13** (`usr/local/go/VERSION`, layer
  `sha256:f5657497bb46…`). The exact guest binaries were extracted from that
  layer in the local carrick store:
  - `go` driver, SHA-256 `aedb1694ac1516bb…` — ET_EXEC, EM_AARCH64, text base
    `0x11000` (first PT_LOAD `0x10000`), **zero `.rel*` sections**, static
    (no INTERP/DYNAMIC), `.symtab` present;
  - `pkg/tool/linux_arm64/compile`, SHA-256 `5d3ce715273cf3be…` — same shape.
- Ground truth needs the same program at two link bases, which needs a relink,
  so the probe pairs were built with the **version-exact** toolchain
  (`GOTOOLCHAIN=go1.24.13`, `GOOS=linux GOARCH=arm64 CGO_ENABLED=0
  GOFLAGS=-trimpath`):
  - `hello` (2.2 MiB; includes a 10-arm switch and a map global):
    `9533f876…` (default base) / `d2e16297…` (`-ldflags=-T=0x100011000`);
  - `cmd/compile` — **the real Go compiler**: `39238ecb…` / `807453c4…`.
- Transfer to the exact image binaries is not assumed, it is checked: the
  rebuilt `compile` twin and the image's `compile` have identical GC-mask
  shape (97,170 mask words, 31,430 pointer bits in both), identical itab count
  (443), identical section layout (rodata differs by 0x20 bytes of build ID).
  The census mode of the probe (`--exact`) records this.

## 2. Method: the two-base diff is exact ground truth

`-ldflags=-T=0x100011000` links the identical program with every allocated
section shifted by exactly `delta = 0x1_0000_0000` (verified per-section;
sizes byte-identical, only DWARF — not loaded — differs in size). Therefore a
word-by-word compare of section contents enumerates base-dependence **exactly**:

- an 8-byte word whose two values differ by exactly `delta` is an
  absolute-address site (must be fixed by +delta at load);
- any other difference is flagged separately — across both pairs the only such
  diffs are the content-hash build IDs (7 words, all inside
  `cmd/internal/objabi.buildID.str`), i.e. **no unexplained or misaligned
  differences: every base-dependent word is 8-aligned and shifts by delta**.

This is strictly stronger than the planned `movz`/`movk`/literal-pool text
scan: any absolute immediate materialization in `.text` would produce
differing text bytes between the arms. There are none.

## 3. Results

### 3.1 The text segment is fixup-free (and jump tables are absent)

Zero absolute sites in `.text` in both pairs (8.8 MiB of compiler text).
AArch64 Go codegen reaches every symbol PC-relatively (`adrp`+`add`), and
`ADRP`'s page-delta is invariant under a uniform shift. No `.jump`/jump-table
symbols exist in either binary, and none could hide in text (zero diffs). The
often-cited text-relocation nightmare simply does not exist on this lane.

### 3.2 The absolute-site census (cmd/compile pair)

| section | abs sites | notes |
|---|---:|---|
| `.text` | **0** | fixup-free |
| `.rodata` | 56,611 | 50,702 in **symbol-less** blobs; 3,473 in `go:itab.*`; 2,436 in named tables |
| `.data` | 27,409 | 27,275 in `gcdatamask`; **134 excluded by design** (§3.3) |
| `.itablink` | 443 | `moduledata.itablinks` backing store |
| `.noptrdata` | 264 | `runtime.firstmoduledata` (33) + `..inittask` records + misc |
| `.go.fipsinfo` | 9 | `go:fipsinfo` layout known |
| `.gopclntab` | 1 | `pcHeader.textStart` — everything else is offset-based |
| total | **84,737** | hello: 6,600 with the same shape |

`.bss`/`.noptrbss` are SHT_NOBITS: no file bytes, so **no baked pointers are
possible** — bss pointers are runtime-initialized and need no fixup. (That
half of the hypothesis is fine; it is also the empty half.)

### 3.3 The GC-bitmap escape hypothesis, killed precisely

The mechanism is real and was decoded from the binary: `moduledata`
(go1.24.13 `runtime/symtab.go:394`) carries `gcdata`/`gcbss` GC *programs*;
`modulesinit` (`symtab.go:535`, mask build at `:544-546`) expands them via
`progToPointerMask` (`runtime/mbitmap.go:1494`, bytecode documented at
`:1505-1520`, `runGCProg` at `:1523`) into one bit per pointer-word of
`[data,edata)`/`[bss,ebss)`; the GC scans exactly those ranges with those
masks (`runtime/mgcmark.go:169,175`). The probe implements the same decoder
and gets a clean decode (97,170 mask words for `.data`, matching
`edata-data`).

Measured against ground truth, the mask covers 27,275 of 27,409 `.data`
absolute sites — and **the 134 misses are not noise, they are policy**, all
holding `.rodata` addresses (`os.Kill`, `flag.ErrHelp`, `io.EOF`-alikes,
`runtime.stringEface`, plus 44 anonymous):

- **Interface first words.** `cmd/compile/internal/typebits/typebits.go:56`
  (go1.24.13): *"The first word of an interface is a pointer, but we don't
  treat it as such."* Every statically-initialized `error`/`any` global bakes
  an absolute itab/`_type` pointer the GC deliberately calls a scalar.
- **Pointers to not-in-heap types.** `typebits.go:30`: pointers to
  `NotInHeap` types are excluded so GC/stack-copying never see them —
  `moduledata` itself is `sys.NotInHeap`, as are `initTask` records
  (94 `..inittask` symbols carry raw init-function pointers in `.noptrdata`).

And the mask says nothing about the dominant mass: **56,611 `.rodata` sites**
(GCData `*byte` pointers, `abi.Name` byte pointers, struct-field slices,
generic dictionaries (`..dict.*`), funcval records, anonymous readonly
composites) — the GC never scans rodata *because* those pointers can never
point to the heap, which is precisely why they are all link-time absolute.
**The set relocation needs and the set the GC needs are near-complements.**

### 3.4 What all known-layout mechanisms together can enumerate

Crediting everything a version-pinned Go-aware loader could walk —
`gcdatamask` (27,275) + `moduledata`'s own fields (33, layout known) +
`.itablink` (443) + every itab's known layout via `itablinks` (3,473) +
`pcHeader.textStart` (1) + `go:fipsinfo` (9) + `go:main.inittasks` (91) and
generously the rest of `.noptrdata` (231) — reaches **≈31,600 of 84,737
(37%)**. The residual **≈53,100 sites (63%)** live in symbol-less packed
rodata with **no complete enumeration root**: `typelinks` is a partial index
by design (interface-conversion types only), types referenced only from code
are reachable from no table, and anonymous readonly composites
(string-header arrays, `..stmp`-class temporaries) are reachable from
nothing at all. A type-graph walker cannot be *proven* complete, and the only
verifier — the two-base diff — requires a second link, which an unmodified
guest binary does not offer. A single missed site is silent memory
corruption in the guest compiler.

**Answering the three framing questions directly:** (1) No — data/bss
bitmaps miss address-words by design (iface word 0, not-in-heap, everything
scalar-typed as `uintptr`); (2) text needs **zero** fixups — the clean
outcome — but that does not rescue the route; (3) `moduledata`'s own 33
absolute fields are trivially fixable via the known per-version layout — the
smallest class in the census.

## 4. Cost, for the record (it was never the blocker)

Had enumeration been sound: 84,737 fixups is a single linear pass over ~3 MB
of load segments — single-digit ms cold, and cacheable per content-digest
exactly like the DSR store, so the ~61 execs/build (a handful of distinct
binaries) amortize to near zero against the 7.2 ms/exec chain floor and the
1.4–5.4 CPU-s of removable translation. The economics were excellent; the
soundness is what fails.

## 5. The `gobin` crate (evaluated on request)

[`gobin`](https://crates.io/crates/gobin) v0.4.0 (2026-06-27, Apache-2.0 —
license-compatible with this workspace's `Apache-2.0 OR MIT`): a genuine
Go-binary metadata parser, not just a pclntab reader — it tracks `moduledata`
layouts across Go 1.16–1.27 (including 1.27's V5 layout, which *removes* the
`typelinks`/`itablinks` slices — note the version fragility that implies),
parses type descriptors, itabs, build info, and `moduledata.inittasks`, for
ELF/Mach-O/PE/Wasm. Its documentation does not expose the `gcdata`/`gcbss`
programs or data/bss bounds as API. **Verdict: partial / moot.** As a parser
it could have replaced this probe's hand-rolled moduledata parsing in a
hypothetical relocator's walker; but the census shows parsing is not the gap
— the missing 63% of sites have *no metadata to parse*, so no parser closes
the soundness hole. Young project (10 commits, 0 stars) — fine for a probe,
thin for a load-bearing dependency; not adopted here.

## 6. What would overturn this verdict

A complete enumerator whose output matches the two-base ground truth
(84,737/84,737 on `cmd/compile`) using only what an unmodified stripped-able
binary guarantees. The named blockers make that implausible: iface word 0
and not-in-heap pointers are outside GC metadata by compiler policy, and
anonymous rodata composites are outside every table. DWARF could name some
globals' types but is optional, strippable, and absent for anonymous
composites. Until such an enumerator exists and is verified, this route is
dead — not "hard", dead, because it cannot even *verify* itself per-binary
at load time.

## 7. Head-to-head and recommendation

- **This route (Route C): UNSOUND — closed.** It was the only candidate that
  removed translation for ET_EXEC at zero per-syscall cost; it cannot be
  made safe.
- **Micro-vmm (Route A): the only live route** for the arm64 ET_EXEC lane.
  Its syscall tax is measured viable (5.9 µs floor / ~18 µs realistic vs
  15.8–60.8 µs kill thresholds); its prize is bounded ~1.4x CPU on the build
  lane, landing near 8x — per the standing docs. This verdict removes the
  "unless relocation works" hedge from that decision: the micro-vmm design
  spike is now unconditionally the next step for this lane, and it is the
  fallback for *all* non-PIE guests, not just Go.
- **Guidance nugget (Route E's sibling, user action only):** a guest binary
  built with `-ldflags=-T=0x100011000` is an ET_EXEC whose VAs all sit above
  the 4 GiB floor — it needs **no relocation and no PIE** to be tier-D
  eligible in principle. carrick cannot do this to unmodified binaries, but
  it is worth documenting for users who control their builds, alongside
  `-buildmode=pie`.
- Scope honesty: everything here is the arm64 canonical (Go ET_EXEC) lane.
  The PIE lane's tier-D program and the per-op amplification program are
  untouched by this verdict.
