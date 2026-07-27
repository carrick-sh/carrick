# File-backed AOT translation cache: getting DSR code out of `MAP_JIT`

**Status:** superseded after Stage 1 by
[`2026-07-26-container-lifetime-translation-cache-design.md`](2026-07-26-container-lifetime-translation-cache-design.md).
The Mach-O emitter and its measurements remain authoritative; the persistent
cross-run store, environment-gated rollout, and per-block replay stages do not.
**Lane:** Darwin/aarch64 native (DSR) — the shipped default backend.
**Motivating measurement:** a guest `fork(2)` costs 567 µs more than it needs to,
because our translation cache lives in `MAP_JIT` memory.

---

## 1. The problem, measured

Every number here was measured on this box (macOS 27.0, build 26A5388g,
`xnu-13432.0.94.501.4`, Apple M4 10-core, quiet, DTrace with the matching KDK).
Nothing in this section is inferred.

### 1.1 `MAP_JIT` is the single largest remaining fork cost

Round-robin ×5, 64 MiB of executable code, otherwise-identical process, entry
count held constant with gapped fillers:

| 64 MiB executable mapping | fork p50 | delta |
|---|---|---|
| none (baseline) | 420 µs | — |
| **`dlopen` of an ad-hoc-signed dylib** | 414 µs | **−6 µs** |
| **`mmap(MAP_JIT)`** | 987 µs | **+567 µs** |

File-backed executable code is **free**. `MAP_JIT` costs **+567 µs on every
fork**, and the penalty scales with the *range* of the mapping (0.117 µs per
page of VA, resident or not) — not with how much of it we actually use.

### 1.2 Why: `MAP_JIT` is classified `COPY_NONE`

`vm_map_enter` assigns `MEMORY_OBJECT_COPY_NONE` to any `entry_for_jit` mapping
(`osfmk/vm/vm_map.c:3537`). `vm_map_fork_compute_extended_inheritance`
(`vm_map.c:12601-12676`) then routes a `VM_INHERIT_COPY` entry whose
`copy_strategy != SYMMETRIC` to **`EXT_COPY_SLOW_PATH`** — `vm_map_fork_copy` →
`vm_map_copyin_internal_for_entry` → `vm_object_copy_strategically`, which
eagerly copies and frees pages instead of resolving COW lazily. And
`vm_map.c:11809` forces the *copy* of a `used_for_jit` entry to `COPY_NONE`
too, so the property is hereditary.

Observed in vivo, 503 kernel samples under `vm_map_fork` in a real 130-fork
carrick run: **89.5% is `vm_map_copyin_internal_for_entry`** (the slow path), of
which ~94% is `vm_object_copy_slowly`. `vm_object_copy_delayed` — the
`COPY_DELAY` route — got **2 samples (0.4%)**, which rules out the libmalloc /
`true_share` hypotheses that looked plausible earlier.

The macOS-native control, with a statistically identical file-backed resident
set, spends **zero** samples in those routines. This is not something every
process pays; it is ours.

### 1.3 The second, larger prize: we re-translate constantly

The fork win is a side effect. The structural cost is that translation output
dies with the process:

- every `go build` / `cpython` / `node` launch re-translates from zero;
- the conformance gate runs 8 workers translating **the same binaries**
  independently, with no sharing;
- `execve` discards the cache outright (`reset_after_fork_for_exec`).

Rosetta 2 solved exactly this: `oahd` AOT-translates each binary **once**, writes
a Mach-O `.aot` to `/var/db/oah/<UUID>/`, and every later execution maps it
**file-backed**. Only genuinely runtime-generated code goes to anonymous memory.
Our `MAP_JIT` region is the equivalent of Rosetta throwing its cache away on
every process — and paying a fork tax for the privilege.

### 1.4 What the platform allows (measured, not assumed)

| attempt | result |
|---|---|
| `mmap(PROT_EXEC)` on an **unsigned** file | **`EPERM`** — AMFI refuses |
| `mmap(PROT_EXEC)` on an already-signed binary | works |
| `dlopen` of a dylib **we generated and ad-hoc signed** | **works**, executed correctly |

The `dlopen` mapping is exactly what we want:

```
__TEXT  100f04000-100f08000  r-x/rwx  SM=COW  .../gen.dylib
```

file-backed, `r-x`, COW. carrick is already ad-hoc signed **without** hardened
runtime, which is the configuration in which loading ad-hoc-signed code is
permitted — the same property that lets us use `MAP_JIT` today.

Costs of that path, measured:

| operation | 16 MiB | 64 MiB |
|---|---|---|
| `codesign -s -` (shell-out) | 0.03 s | 0.08 s |
| `dlopen`, **cold** (validate + page-in) | 183 ms | 421 ms |
| `dlopen`, **warm** (page cache hot) | 0.5 ms | 1.0 ms |
| `dlsym` | 3 µs | 2 µs |

Cold cost is paid once per unit per boot and is **shared by every process that
loads it** — which is precisely the 8-worker and repeated-launch case.

---

## 2. Design

### 2.1 Shape

Translate as we do now, but **publish** completed translation units as
ad-hoc-signed Mach-O dylibs on disk, loaded with `dlopen`. Keep `MAP_JIT` only
for code that genuinely cannot be published ahead of use.

```
guest binary ──► translate ──► emit Mach-O (__TEXT = translated blocks)
                                   │
                                   ├─► ad-hoc sign
                                   ├─► atomic rename into the store
                                   └─► dlopen ──► r-x SM=COW file-backed
```

### 2.2 Non-negotiable constraint: batching

`dlopen` + signing costs ~0.1–0.5 s per unit cold. **One `dlopen` per basic
block is absurd; one per translation unit is fine.** This is an architectural
constraint on the translator, and it is the same trade Rosetta made: AOT the
static body of a binary, JIT only what is genuinely dynamic.

Therefore the cache is **two-tier**:

- **Tier A — published units (file-backed).** Batched translation output for
  code reachable from a known guest binary. Fork-free, exec-surviving,
  process-surviving, shared between concurrent guests.
- **Tier B — `MAP_JIT` scratch.** Genuinely dynamic targets, self-modifying
  guest code, and anything not yet promoted. Keeps today's semantics. Its size
  is what still costs us at fork, so Tier B should stay small and — separately —
  should not be inherited larger than it needs to be.

### 2.3 Cache identity and invalidation

A unit's key must be derivable **without** reading the guest binary twice and
must be stable across machines that share a store:

```
key = H(guest_build_id_or_content_hash, guest_va_range, translator_abi_version, page_profile)
```

- `translator_abi_version` **must** be bumped by any change to emitted code,
  gateway ABI, or `X86DsrContext`/`AArch64` context layout. A stale unit is a
  wrong-code bug, not a slow path.
- The store lives under `CARRICK_HOME`; entries are written to a temp file and
  **atomically renamed**, matching how `oahd` uses `.in_progress` → `.aot`.
- Corrupt or unloadable units must fall back to Tier B, never fail the guest.

### 2.4 What we do NOT do

- **We do not use `VM_INHERIT_NONE` on the JIT region as the primary fix.** It
  measures ~445 µs of the same win, but the child then re-translates from
  scratch: fine for fork→exec, a regression for fork-*without*-exec (Python
  `multiprocessing`, forking servers), which the project must support. It stays
  available as a targeted optimisation for the exec path.
- **We do not raw-`mmap` the cache file `PROT_EXEC`.** Measured `EPERM`.
- **We do not require the hypervisor entitlement or hardened runtime changes.**
  Ad-hoc signing is what we already ship.

---

## 3. Staged plan

Each stage is independently verifiable and names the measurement that proves it.

### Stage 1 — Mach-O emitter — **DONE**

`crates/carrick-native-darwin/src/aot.rs`. Emits a loadable arm64 `MH_DYLIB`
whose `__TEXT` is a caller-supplied code blob, exporting symbols at
caller-chosen offsets. Proven by a test that emits, ad-hoc signs, `dlopen`s,
`dlsym`s and CALLS the code, expecting `42`.

**Result that changes the design: no linker is needed.** `ld` refuses to build a
dylib without `-lSystem` ("dynamic executables or dylibs must link with
libSystem.dylib"), but that is an `ld` policy, not a dyld requirement — dyld
loads a hand-built dylib with **no `LC_LOAD_DYLIB` at all**, which is correct
for a self-contained translated unit. So the per-unit cost is memory work plus a
file write, not two process spawns.

Minimum viable image: 7 load commands — `LC_SEGMENT_64(__TEXT)` with one
`__text` section, `LC_SEGMENT_64(__LINKEDIT)`, `LC_ID_DYLIB`,
`LC_DYLD_INFO_ONLY`, `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_BUILD_VERSION`.

**Traps found getting there** — each cost an iteration and every one will recur
for anyone touching this code:

| symptom | cause |
|---|---|
| `unloadable mach-o file type 1` | the `object` crate writes `MH_OBJECT`; `dlopen` needs `MH_DYLIB`. (`object` was tried and then dropped — it cannot emit a linked image.) |
| `not a mach-o` | `LC_BUILD_VERSION` declared `cmdsize = 32` with `ntools = 0`; it is 24, and the extra 8 bytes were garbage in the command stream |
| `iundefsym != iextdefsym+nextdefsym` | dyld ENFORCES that `LC_DYSYMTAB` index invariant |
| `unknown bind opcode 0xE0` | export trie written into the **lazy-bind** slot of `LC_DYLD_INFO_ONLY` instead of the **export** slot |
| SIGTRAP inside `mach_o::ExportsTrie::valid` | trie child offset emitted as `7` for a true offset of `21` — a fixed-point loop whose search range was too small, failing silently |
| SIGTRAP on the first CALL (loads fine) | signing APPENDS `LC_CODE_SIGNATURE`, growing `sizeofcmds` by 16 and sliding the code out from under the emitted symbol addresses. Reserve header slack, as real linkers do. |
| `sizeofcmds` mismatch (caught by `debug_assert`) | `LC_ID_DYLIB`'s name must be NUL-terminated and padded to the command's declared size, not merely 8-aligned |

### Stage 2 — Publish/load path behind an env flag

`CARRICK_DSR_AOT_CACHE=1` routes completed units through emit → sign → `dlopen`,
with Tier B fallback on any failure.

*Proves it:* a guest runs correctly with the flag on; the loaded unit appears in
`vmmap` as `r-x SM=COW` file-backed; Tier B usage drops.

### Stage 3 — Fork win

*Proves it:* `perf_fork_scale` fork p50 with the flag on vs off, interleaved on a
quiet box. **Predicted: −567 µs** at a 64 MiB-equivalent published set, from §1.1.
If the delta is not within ~20% of that, the published set is not actually
carrying the code and Stage 2 is not really done.

### Stage 4 — Persistence and sharing

Store lookup by key across processes and runs.

*Proves it:* second launch of the same guest performs zero translation
(`translations=0` in the DSR profile) and the second process's `dlopen` is warm
(~1 ms, not ~400 ms). Gate wall-clock with 8 workers should drop measurably.

### Stage 5 — Amplification ratchet

Record translation counts + cache hit rate as a CI-visible metric so a
regression that silently re-translates is caught.

---

## 4. Open questions and honest risks

1. **Relocations remain unproven, and are now the top risk.** Stage 1 emits
   position-independent code with no fixups. Real translated blocks reference
   the gateway, sensitive-instruction helpers and each other. Whether those
   become symbol imports, a GOT, or absolute addresses baked per unit is
   undecided — and note that the "no `LC_LOAD_DYLIB`" property that makes
   emission cheap holds only while units stay self-contained. Importing a
   symbol reintroduces bind opcodes and a load-dylib command.
2. **Signing is the last remaining process spawn.** 0.03–0.08 s measured via the
   `codesign` binary. The `apple-codesign` crate (MPL-2.0, inside our deny
   allowlist) exposes `MachOSigner` for in-process ad-hoc signing and would
   remove it — at the cost of a substantial crypto/ASN.1 dependency tree for
   what, in the ad-hoc case, is SHA-256 page hashes plus a CodeDirectory blob.
   Check the transitive licences under `cargo deny` BEFORE adopting it.
3. **Cold `dlopen` at 421 ms for 64 MiB** is large. Units should be sized so a
   cold load is amortised; this argues for several medium units, not one huge
   one. Unmeasured: the knee of that curve.
4. **W^X during emission.** Tier A code is written to a *file*, not to RWX
   memory, so the `pthread_jit_write_protect_np` dance does not apply — but the
   emitter must not accidentally keep a writable mapping of a signed file.
5. **Store lifetime, eviction, and multi-version guests** are unspecified.
   Rosetta gets SIP protection; our store is ordinary user-writable state, so a
   tampered unit is a code-execution vector. **Units must be validated by
   signature *and* keyed by content hash of the guest input.**
6. **Non-macOS lanes are untouched.** FreeBSD/NetBSD keep `MAP_JIT`; NetBSD
   already returns `ForkChildJit::Fresh` for its own reasons.

---

## 5. Appendix: why the earlier hypotheses died

Recorded so they are not re-proposed.

| hypothesis | verdict |
|---|---|
| VM-map *holes* / sparsity | refuted — 0 cost per hole; an ordinary process is also ~500 GiB sparse |
| VA spread | refuted — 0 |
| bytes / resident pages | refuted **on SYMMETRIC objects**; on `COPY_NONE` it is ~0.95 µs/resident page |
| entry **count** | real but small — 0.221 µs/entry; ~57 µs of prize left after `58a84062` |
| `true_share` | refuted — every `SM_TRUESHARED` entry is system-owned (dyld, libsystem, libmalloc) |
| `COPY_DELAY` / libmalloc magazines | refuted in vivo — 0.4% of `vm_map_fork` samples |
| progressive COW ratchet across forks | refuted — iteration 0 is the *most* expensive, then decays flat |
| carrick's own fork code | refuted — parent-side phases total 12–14 µs of 1374 µs |
