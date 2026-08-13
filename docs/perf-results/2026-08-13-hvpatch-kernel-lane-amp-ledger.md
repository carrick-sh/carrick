# The kernel lane's first AMP1 ledger — and it moves the target off syscalls

**Recorded 2026-08-13**, immediately after KN
([evidence](2026-08-13-hvpatch-kernel-namei.md)). This is the first
amplification ledger ever taken of the `hvpatch` backend: AMP1 previously
refused any target that did not name `--exec-backend native`, so the lane this
tree is measured against had never been censused by the tree's own instrument.
That refusal is fixed (`8b2f751dc`); this is the result.

## Provenance

| Field | Value |
| --- | --- |
| Commit | `8b2f751dc` (tree clean) |
| Signed binary SHA-256 | `a197837fcfde2e10c1799c591aa42db868c0338d1a59183bc607cce1423d43e4` |
| Host | macOS 27.0 `26A5406e`, Darwin 27.0.0 arm64, Apple M4, 10 logical (4P + 6E) |
| Image | `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b` |
| Backend | `--exec-backend hvpatch` |
| Artifact | `target/perf/kn-amp/kn-after-2.ledger.json`, schema `carrick.amplification-ledger.v1` |
| Result | `BUILD_OK`, exit 0 |

**Authenticated and closed.** Every per-op sum equals the capture's independent
total (`closure` section), `inherited_service_ends` is 0, and the reader refuses
a stream that cannot prove itself. `probable_instrument` is zero, so no
libdtrace `kdebug_trace*` traffic contaminated the census.

**Traced.** Counts are what this measures. The CPU-ns figures are `vtimestamp`
sums — on-CPU time inside the host call — which is a same-instrument quantity
and is used only for ranking, never as an absolute against an untraced budget.

## Headline

| | value |
| --- | ---: |
| guest Linux syscalls | 73,747 |
| host macOS syscalls | 242,171 |
| **overall amplification** | **3.28x** |
| host syscall CPU | 1.014 s |
| mach traps | 42,284 (0.091 s) |
| `as_fault` | **279,987** |
| `zfod` | **230,298** |
| `cow_fault` | 8,350 |

For comparison, the pre-KN census
([ledger](2026-08-13-hvpatch-build-amplification-ledger.md)) reported 4.71x
overall. Guest counts match almost exactly across the two captures (3,272 vs
3,268 `openat`; 3,961 vs 3,967 `newfstatat`; 282 vs 283 `mkdirat`), so the same
workload was measured — but they are DIFFERENT PROGRAMS
(`syscall-amplification.d` vs AMP1), so read the improvement as indicative,
not as a controlled before/after.

## KN's gate, answered

| guest op | guest calls | host calls | amplification | pre-KN | gate |
| --- | ---: | ---: | ---: | ---: | ---: |
| `openat` | 3,272 | 58,074 | **17.75** | 32.78 | ≤ 2.0 |
| `newfstatat` | 3,961 | 28,015 | **7.07** | 13.84 | ≤ 2.0 |
| `mkdirat` | 282 | 12,741 | **45.18** | 90.96 | ≤ 2.0 |
| `unlinkat` | 156 | 7,693 | **49.31** | — | ≤ 2.0 |
| overall | 73,747 | 242,171 | **3.28x** | 4.71x | ≤ 2.0x |

**KN roughly halved every path-op ratio and did not meet its gate.** Recorded
as a partial: the mechanism is right and the remaining factor is real. The
dominant host call inside `openat`, `newfstatat`, `mkdirat` and `unlinkat`
service windows is still `openat` itself, so cap-std is still walking something
— the leaf, the fallback cases, or a prefix the cache could not serve.

Path operations cost **384 ms** of the 1,014 ms of host-syscall CPU (37.8%).
Driving them to the gate would recover at most ~326 ms — on a build whose
untraced total is ~4.1 CPU-s, that is **under 8%**. The gate is worth meeting
for its own sake; it is not worth mistaking for the goal.

## The finding: faults, not syscalls

The census puts **279,987 `as_fault` and 230,298 `zfod`** on this build. At the
6.42 µs single-threaded fault cost this tree measured on 2026-08-01, 280k
faults is **~1.8 CPU-s** — which is, to within its own error, the ENTIRE
overhead the goal requires removing (~1.97 CPU-s).

Attributed by the guest operation being serviced:

| guest op | guest calls | host calls | `as_fault` | `zfod` | host CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| **`mmap`** | 1,966 | 2,045 | **151,375** | **150,749** | 5 ms |
| **`execve`** | 68 | 8,306 | **45,815** | **45,430** | 36 ms |
| `clone` | 358 | 6,993 | 2,102 | 1,749 | 9 ms |
| `carrick-only` | 28,890 | — | 70,678 | 30,896 | 404 ms |
| `madvise` | 381 | 15 | 511 | 29 | 0 ms |
| `munmap` / `mprotect` / `brk` | 92 | 5 | 27 | 0 | 0 ms |

Read the `mmap` row carefully, because it inverts the usual shape:

> **`mmap` costs 1.04 host syscalls per guest call and 76.7 zero-fill faults.**
> The syscall side is already essentially perfect. The cost is 150,749 pages —
> **2.36 GiB at 16 KiB pages** — being zero-filled per build, INSIDE the
> service window, which is carrick's own host-side touching, not the guest
> running.

`execve` shows the same shape at 668 `zfod` per exec.

This is the same class of finding the native lane resolved on 2026-08-07, where
a whole-range anonymous scrub was replaced kernel-side and in-window `zfod`
collapsed 553k → ~723
([anon-reuse-remap](2026-08-07-anon-reuse-remap.md)). **That work was never
carried to the kernel lane.** Note the native fix does not port directly:
`CARRICK_DSR_ZERO_REMAP` lives in `carrick-dsr-aarch64::mapped_memory`, and the
HVF lane's `HvfInner::zero_guest_backing` (`carrick-vmm-hvf/src/trap.rs:4795`)
is a plain `write_bytes` memset with no remap path. Remapping is not
straightforwardly available there either — the arena is `hv_vm_map`'d into
stage-2, so replacing the host pages beneath a live IPA would leave the guest
looking at the old physical pages.

### The mechanism, named

Not left open. A `vminfo:::zfod` aggregation screened on the `mmap` service
window (`hvpatch-syscall-service-begin` arg3 == 222) and keyed on the faulting
user PC, printed on a tick while the process was still alive — symbolication at
`END` runs after the traced child has exited and yields raw addresses:

| faulting symbol | in-window `zfod` |
| --- | ---: |
| **`libsystem_platform.dylib`__bzero`** | **145,966** |
| `_platform_memset` | 301 |
| `HvfVmState::write_guest_bytes` | 232 |
| everything else | ~32 |
| total | 146,531 |

With `ustack(7)`, **145,429 of them have exactly one caller**:

```text
libsystem_platform.dylib`__bzero+0x40
carrick`carrick_runtime::dispatch::mem::…::mmap+0xda0
carrick`…::dispatch_threaded_captured
```

**Neither is the guest touching its own memory:** this is inside carrick's own
service window, with the guest stopped.

### CORRECTION — the first attribution of that `__bzero` was wrong

This document originally named `let mut bytes = vec![0; length_usize]`
(`dispatch/mem.rs:2792`), the eager snapshot buffer for a *file* mapping, and
concluded that the file-backed lowering's `!PROT_EXEC` guard was the blocker.
**That was inferred from code reading and is refuted by measurement.** The
inference was: the anonymous branch allocates `Vec::new()`, so a `bzero` inside
`mmap` must come from the file branch. It does not — the anonymous path zeroes
through a *different* call that inlines into the same function.

`scripts/dtrace/hvpatch-mmap-shape-census.d` buckets every guest `mmap` by
(anonymous?, sharing, prot) and attributes each bucket's in-window faults:

| mmap shape | calls | bytes requested | in-window `zfod` |
| --- | ---: | ---: | ---: |
| **anon / private / RW-** | 1,261 | **3.11 GB** | **145,453** |
| file / shared / R-- | 56 | 15.3 MB | 890 |
| file / private / R-X | 2 | 3.5 MB | 433 |
| anon / private / `---` (PROT_NONE reserve) | 525 | **83.7 GB** | **4** |
| file / private / R-- | 14 | 380 KB | 27 |
| everything else | 70 | 4.3 MB | 2 |
| total | 1,928 | — | 146,809 |

**99.1% of the faults are ANONYMOUS private read-write mappings.** All file
mappings together contribute ~1,350, so the file-backed lowering and its
`PROT_EXEC` guard are a **red herring for this term** — a whole phase would
have been aimed at 0.9% of it.

Note also that **PROT_NONE reserves are already correctly lazy**: 525 calls
reserving 83.7 GB take *four* faults between them. Reservation is not the
problem; commitment is.

### The real chain, exactly

```text
dispatch/mem.rs  mmap  →  GuestMemory::zero_anonymous_reuse
                             (DEFAULT impl, carrick-guest-mem/src/lib.rs:456)
                          →  zero_backing
                          →  HvfVmState::zero_guest_backing
                             (carrick-vmm-hvf/src/trap.rs:4795)
                          →  core::ptr::write_bytes(…, 0, length)  →  __bzero
```

The whole chain inlines into `mmap`, which is why the stack shows `__bzero`
called directly from it.

**The gap is now a single sentence.** `zero_anonymous_reuse` is a trait method
with a memset default. The native lane **overrides** it
(`carrick-dsr-aarch64/src/mapped_memory.rs:4252`) with the 2026-08-07 remap
that collapsed its in-window `zfod` 553k → ~723. **The HVF backend does not
override it at all**, so the kernel lane takes the memset default and pays
145,453 faults for it.

The three `zero_backing` call sites in `dispatch/mem.rs` (`brk` shrink,
`mremap` reuse, `MADV_DONTNEED`) remain confirmed non-sources — those three
guest ops produce 29 `zfod` between them.

**How much of that 3.11 GB genuinely needs scrubbing is a separate open
question.** The arena skips zero-fill above its high-water mark and scrubs
below it; ~77% of the requested anonymous bytes are being touched, so either
the reuse is real or the high-water heuristic is being defeated. Answering that
decides whether KF should make the scrub cheap or remove the need for it.

### A consequence that changes the fix

The buffer is zeroed and then immediately overwritten, so the obvious
micro-fix is to stop double-writing. **That would not remove the faults.** The
page is faulted on FIRST touch either way; skipping the `bzero` only means the
`copy_from_slice` takes the fault instead. It halves memory traffic and leaves
the 150,749 faults exactly where they are.

The fault only disappears if the buffer is never materialized — i.e. if the
mapping is lowered to a host file mapping and Darwin demand-pages it. That
lowering already exists (`mmap_file_backed_lowering_enabled`, default on) and
is refused here by its own guards, of which the load-bearing one is
`!prot_flags.contains(PROT_EXEC)`: program text is exactly the large,
frequently-mapped case, and it is excluded because "executable content must
flow through the write path's W^X/translation-invalidation metadata"
(`dispatch/mem.rs:2755`). Whether that reason still applies on the kernel lane
— which patches static text rather than translating it — is KF's first design
question, and it is a correctness question, not a performance one.

Also not established: the 6.42 µs per-fault cost was measured on the native
lane in a different context, so the ~1.8 CPU-s figure is an order-of-magnitude
estimate, not a measurement. It is strong enough to RANK the work and not
strong enough to bank.

## Two smaller corrections this census forces

- **`carrick-only` is 11.9% of host calls here, not 30.1%.** Its 404 ms of CPU
  is dominated by **`clonefileat`: 319 ms in 21 calls** — the rootfs COW seed,
  a one-time container setup cost, not per-syscall runtime overhead. Steady-state
  `carrick-only` is closer to 85 ms. The earlier 30.1% figure came from a
  different program and should not be quoted against this one.
- **`nanosleep` is called 13,629 times** by the guest for 28 ms of host CPU at
  1.34x. Cheap per call, but that population is worth understanding — it is the
  second-largest guest syscall count in the run.

## Next

1. Attribute the `mmap`-window faults to their exact host-side origin. Until
   that is named, the largest term in the build is unexplained.
2. Then decide the lowering. The native lane's answer — let Darwin's zero-fill
   deliver a pre-zeroed page instead of writing one — is the right shape, and
   the stage-2 constraint means the kernel lane needs its own expression of it.
3. Path amplification stays on the list, honestly sized at under 8%.
