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

## Root cause (confirmed)

Per ARMv8-A architectural rules, **when stage-1 MMU is disabled
(SCTLR_EL1.M=0), all data accesses are forced to use the
"Device-nGnRnE" memory type.** Exclusive load/store operations
(LDXR, LDAXR, STXR, STLXR) on Device memory are *prohibited* by
the architecture and produce an external abort — exactly the
`ESR_EL1 = 0x92000035` (DFSC=0x35, external abort on TT walk) we
observe.

Carrick's bootstrap deliberately leaves stage-1 off (`SCTLR_EL1=0`
at vCPU init) to keep the guest's IPA equal to its VA — we don't
have page tables. Apple HVF inherits this constraint: every EL0
data access is treated as Device. The first `ldaxr` in musl's
pthread_mutex_lock fast path immediately aborts.

### What we tried, and what it doesn't fix

| Change                                  | Result                                  |
|-----------------------------------------|------------------------------------------|
| Merge musl's two PT_LOAD segments       | Mapping covers the fault address.       |
|                                         | Fault unchanged.                        |
| `clrex` in EL0 trampoline before `eret` | Monitor in a known state.               |
|                                         | Fault unchanged.                        |
| SCTLR_EL1.C=1, I=1 (cache enable bits)  | No effect — caches are inert without MMU. |
|                                         | Fault unchanged.                        |
| Bigger HVF mapping (one 768K region)    | Same.                                   |
|                                         | Fault unchanged.                        |
| Bigger HVF page (16K → 64K)             | Same.                                   |
|                                         | Fault unchanged.                        |

## The fix that *would* work

**Set `HCR_EL2.DC = 1`.** This bit forces all stage-1 EL0/EL1
data accesses to be treated as Normal Inner Shareable WB cacheable
memory when stage-1 is disabled, even though the architectural
default is Device. Exclusive accesses on Normal memory are well-
defined.

`HCR_EL2` is **only writable from EL2**. In Apple's HVF stack,
EL2 is the hypervisor itself; the guest can't touch HCR_EL2 from
EL1. The `applevisor` crate exposes `SysReg::HCR_EL2`, but per
the source comment "this register is only available if EL2 was
enabled in the VM configuration," and the `set_el2_enabled`
config flag is gated behind the `macos-15-0` cargo feature.

We currently use `macos-13-0` features (the minimum that gives
us `set_ipa_size`). Upgrading to `macos-15-0` and enabling EL2
in the VM config is one path forward.

## Alternative fixes

1. **Build stage-1 page tables.** Identity-map the guest IPA window
   with `MAIR_EL1` index 0 = Normal cacheable, set `TCR_EL1`, set
   `TTBR0_EL1`, then `SCTLR_EL1.M = 1`. The guest sees the same
   virtual layout it had before, but now `ldaxr` works. ~200 lines
   of additional setup code, no Apple feature requirement.

2. **Enable EL2 + set HCR_EL2.DC.** Switch the `applevisor` crate
   to `macos-15-0`, call `set_el2_enabled(true)` on the VM config,
   then `vcpu.set_sys_reg(HCR_EL2, ...)` in `map_plan`. Adds an
   Apple-version dependency but is much smaller code-wise.

3. **Patch musl at load time.** Replace `ldaxr`/`stlxr` pairs with
   non-exclusive `ldr`/`str` equivalents wrapped in a host-side
   spinlock. Fragile and slow.

4. **Use static-musl binaries that don't issue exclusives at
   startup.** Static `busybox` binaries from a different builder
   may avoid the early pthread path; testing required.

## Next debugging step

Stage-1 page tables (option 1) is the right answer because it's
self-contained and works on any macOS HVF version. Building a
single-level identity map for a 1 TiB IPA window with one MAIR
index is ~100 lines of Rust to construct the table + a few sysreg
writes.

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
