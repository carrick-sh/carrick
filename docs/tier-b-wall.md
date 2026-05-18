# Tier B current wall — `ldaxr` on a stage-2-mapped page

## Status

* **Tier A**: working end-to-end. `carrick run-elf ...hello` returns
  `"hello from carrick\n"` exit 0 in 2 traps.
* **Tier B (Alpine busybox)**: musl `ld-musl-aarch64.so.1` boots six
  syscalls deep (set_tid_address, brk×2, mmap, mprotect×2) then takes
  a deterministic, recurring stage-2 fault.

## Repro

```sh
./scripts/debug-tier-b.sh   # rebuilds + signs + runs alpine busybox with trace
```

Trace shows:

```
TRAP esr_el1=0x92000035 (ec=0x24, DFSC=0x35)
     pc=0x20404  elr=0x80000631d8  far=0x80000c2ab4
     x0=0x80000c2ab0  x1=0x80000c2ab4
```

`0x80000631d8` in `ld-musl-aarch64.so.1` is the first instruction of
musl's `pthread_mutex_lock` fast path:

```
631c4: ldr   w1, [x0]              ; x0 = pointer to a mutex object
631c8: tst   x1, #0xf
631cc: b.ne  ...                   ; non-zero -> slow path
631d0: add   x1, x0, #0x4          ; x1 = &mtx->_m_lock
631d4: mov   w3, #0x10             ; PI flag
631d8: ldaxr w2, [x1]              ; <-- exclusive load faults here
```

The mutex is at IPA `0x80000c2ab0`; the LDAXR loads from `+4` =
`0x80000c2ab4`. With our segment-merge fix in place, the *entire*
musl image (text + .rodata + .data + .bss) is now a single
contiguous HVF mapping `0x8000000000 .. 0x80000c4000`, RWX
post-quirk-escalation, covering the fault address. The mapping
exists; the LDAXR still faults.

## Decoding the syndrome

`ESR_EL1 = 0x92000035`:

* EC (bits 31:26) = `0x24` — *Data Abort taken from a lower Exception
  level.*
* IL = 1 — 32-bit instruction syndrome.
* ISS = `0x2000035`:
  * bit 24 (ISV) = 0 — Instruction Syndrome **not valid**. The CPU
    didn't decode the faulting instruction into the ISS.
  * bit 9 (EA) = 1 — **External Abort**.
  * bit 6 (WnR) = 0 — read access.
  * bits 5:0 (DFSC) = `0x35` — *External abort on a translation
    table walk, level 1.*

DFSC `0x35` means the page-table walker itself got an external abort
while reading the level-1 stage-2 descriptor for IPA `0x80000c2ab4`.
The HVF VM has the mapping (`MAP guest_start=0x8000000000
mapped_size=0xc4000 perms=r+w+x+` is logged at startup); the walk
nonetheless reports external abort.

`ISV=0` is the most suggestive bit. ARMv8 ARM lists several
instruction classes that intentionally do **not** populate the ISS
(see ARM ARM D17.2.43 "ESR_EL1, Exception Syndrome Register, Data
abort exception"); **exclusive load/store** (LDXR, LDAXR, STXR,
STLXR) is one of them. So the syndrome shape is consistent with
"LDAXR on stage-2-mapped guest memory takes an external abort on
this Apple Silicon HVF configuration."

## Hypotheses

1. **Memory attribute mismatch.** ARMv8 requires exclusive memory
   accesses to land on *Normal cacheable inner-write-back* memory.
   Apple HVF's default stage-2 mapping memory type may be Normal but
   the inner/outer cacheability attributes might be set such that
   LDAXR is "unpredictable" or aborts. The applevisor crate exposes
   only `MemPerms` (R/W/X bits), not memory-attribute control —
   `hv_vm_map` doesn't take a `MAIR` index.

2. **Exclusive monitor not configured.** AArch64 exclusive
   instructions require the exclusive monitor to be in a particular
   state on the executing CPU. Some HVF guests need the guest kernel
   to issue `CLREX` early; without it, the first LDAXR is implementation-
   defined behaviour. We don't issue CLREX from our EL0 trampoline.

3. **Apple Silicon E-core vs P-core scheduling.** HVF can migrate
   vCPUs between cores; exclusive monitor state is per-core. A
   migration between LDAXR and its paired STLXR causes the
   exclusive to fail repeatedly — but this is typically an "exclusive
   failed → retry" loop, not an external abort.

4. **HVF refuses LDAXR on stage-2 memory created via `hv_vm_map`.**
   This would be an Apple bug. Apple Silicon HVF is known to have
   restrictions on what instructions guests can run; the default
   `HV_VM_CONFIG` does not enable nested virt or some other features
   guests may want.

Of these, (1) and (4) are the most plausible. (2) is testable by
adding `clrex` to the EL0 trampoline. (3) seems unlikely given the
fault is deterministic, not intermittent.

## Next debugging step

* Try adding `clrex` to the EL0 trampoline ahead of `eret`.
* Try replacing musl in the rootfs with a test stub that does a
  non-exclusive `ldr` from `0x80000c2ab4` and observe whether THAT
  faults. If `ldr` succeeds but `ldaxr` doesn't, the issue is
  isolated to exclusive accesses.
* If exclusive accesses are confirmed broken on stage-2 HVF, we
  can either:
  - Trap-and-emulate by single-stepping past exclusive ops (massive
    perf hit).
  - Patch musl at load time to rewrite `ldaxr`/`stlxr` pairs into
    non-exclusive equivalents + a host-side spinlock.
  - Switch to a musl variant that doesn't issue exclusives on the
    bootstrap path (unlikely to exist).

## What works around it for the demo

Static-PIE binaries that don't use pthread / pthread locks never hit
this path. The fix is either: ship a static-musl variant of busybox
(no `ld-musl` involved), or build a custom busybox that opts out of
locking on early init.

## Reference data

* `objdump -d /tmp/ld-musl.so | grep -B 5 631d8` — disassembly of
  the faulting region in musl.
* Latest run trace: `docs/last-tier-b.trace` (written by
  `scripts/debug-tier-b.sh`).
* The trace knobs `CARRICK_TRACE_REGS=1` and `CARRICK_TRACE_MAPS=1`
  are documented in `docs/lldb-debugging.md`.
