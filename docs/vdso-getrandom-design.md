# vDSO `__kernel_getrandom` — clean-room design

Derived 2026-05-30 from man-pages + LWN prose + **observed** Docker linux/arm64
behavior (strace of a glibc getrandom program) + disassembly of the on-oracle
vDSO binary. **No Linux kernel/glibc source was read** (see
`feedback_no_linux_source`). Oracle: Docker LinuxKit kernel 6.12.76, glibc 2.41.

## ABI (observed)

```c
ssize_t __kernel_getrandom(void *buffer, size_t len, unsigned int flags,
                           void *opaque_state, size_t opaque_len);
```
- Versioned `__kernel_getrandom@@LINUX_2.6.39` (same version node as the other
  aarch64 vDSO syms — hash 0x75fcb89, already in carrick's vdso.rs verdef).
- Args x0..x4; return in x0. Fallback syscall: `mov x8,#278 (__NR_getrandom); svc #0`.

### Query mode — `opaque_len == ~0UL`
Returns 0 and fills `struct vgetrandom_opaque_params { u32 size_of_opaque_state;
u32 mmap_prot; u32 mmap_flags; u32 reserved[13]; }` (64 bytes). **Observed
values:** `size_of_opaque_state=144 (0x90)`, `mmap_prot=0x3 (RW)`,
`mmap_flags=0x28 (MAP_ANONYMOUS 0x20 | MAP_DROPPABLE 0x8)`. glibc 2.41 REQUIRES
query mode to work — garbage here → wrong-sized/flagged state page.

### Observed runtime protocol (strace)
1. First getrandom() → glibc `mmap(NULL,4096,RW,MAP_DROPPABLE|MAP_ANON,-1,0)` for
   the per-thread opaque state (144 bytes used).
2. vDSO seeds via ONE real `getrandom(key,32,0)` syscall, then serves a userspace
   ChaCha20 batch (96-byte/0x60 refill); 16 user calls → 1 syscall.
3. `GRND_NONBLOCK` punts to the real syscall; `GRND_RANDOM`/`GRND_INSECURE` served
   from the batch. Opaque-state fields: +0x80 generation snapshot, +0x88 batch
   position, +0x89 in_use. (The older LWN/919008 `vgetrandom_alloc`/256-byte
   design is PRE-MERGE — does NOT match shipped 6.11+.)

## carrick must provide
- Export `__kernel_getrandom@@LINUX_2.6.39` from the hand-built vDSO ELF
  (`crates/carrick-mem/src/vdso.rs`; bump NSYM, reuse the existing verdef/hash).
- A `__kernel_getrandom` body. **Minimum viable (P1):** implement QUERY mode
  correctly + ALWAYS fall back to the syscall (`mov x8,#278; svc #0`) for the
  generate path. Functionally correct (random bytes via syscall), no userspace
  crypto. A partial/garbage impl REGRESSES (glibc trusts the vDSO); query MUST be
  right.
- mmap dispatch must ACCEPT flag `0x8` (MAP_DROPPABLE) — glibc passes 0x28 for
  the state page; reject → vgetrandom init fails (best case: per-call syscall).
  Treat as a normal private-anon mapping (no drop-under-pressure needed).
- `__NR_getrandom` (278) syscall must work (fallback + seed). Verify it does.
- An RNG-data area the function reads: generation u64 @ data-page base + is_ready
  byte @ data+8, placed at the kernel-conventional spot (page before the vDSO
  code; regular + time-ns mirror). For a fallback-only stub a single zeroed page
  suffices (generation unused).

## Phased plan
- **P1 (M):** symbol + query + syscall-fallback body in `tools/vdso_fns.s` →
  `VDSO_CODE`; mmap accept `MAP_DROPPABLE` (`dispatch/mem.rs`); vvar RNG-data page
  (zeroed) disjoint from the existing time vvar. Probe `getrandomvdso` (resolve
  symbol, query returns 144/0x3/0x28, getrandom() returns correct-length bytes)
  vs ubuntu:24.04 oracle. **This satisfies "all vDSO interfaces" functionally.**
- **P2 (L):** userspace ChaCha20 — a `no_std` zero-relocation Rust PIC blob
  (`tools/build-vdso-getrandom.sh`) + generation-counter reseed (carrick bumps
  generation on host reseed / fork). Delivers the syscall-free fast path. Verify
  syscall-count drop via carrick trace.

## Risks
- Never silently drop MAP_DROPPABLE (would EINVAL glibc's state mmap).
- Keep the RNG-data page disjoint from the time vvar; single-page state guard
  (the code rejects if `(opaque_state & 0xfff) + 0x90` crosses a page).
- On fork, bump the generation so a child's cached batch reseeds (P2 only).

Full research (per-agent ABI/embed/synthesis): workflow run `wf_c485321a-1cb`.
