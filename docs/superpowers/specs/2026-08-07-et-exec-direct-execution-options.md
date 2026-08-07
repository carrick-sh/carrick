# ET_EXEC direct execution on Darwin/arm64: a costed options paper

**Date:** 2026-08-07
**Scope:** research + design only, no runtime changes. Answers the single
question the ablation ladder left open: *can an ET_EXEC Linux/arm64 guest
(Go's toolchain, text at low VAs) ever run under carrick's patch-not-translate
tier D on Darwin/arm64 — and if not directly, what is the smallest lever that
recovers most of tier D's 2.76x translation win for it?*
**Verdict up front:** rung 5's **NO is UPHELD for software direct execution and
NARROWED** — the impossibility is specific to running arm64 ET_EXEC as patched
host-native process state; two routes escape it (an HVF stage-1 "micro-vmm" for
arm64; a Rosetta x86_64 address space for amd64 guests only), both proven-real
here, neither a free win, and neither getting the *arm64* `go build` lane onto a
patched path. Recommendation and cheapest decisive experiment in §7.

---

## 0. Licensing note (read first)

This paper reads Apple's **XNU** kernel source (APSL-2.0, publicly published at
`apple-oss-distributions/xnu`, tag `xnu-12377.1.9`). AGENTS.md's clean-room
prohibition is **specifically about Linux/GPL source** — carrick's *Linux ABI*
behaviour must come only from man-pages/specs and the Docker oracle. Reading
**Darwin's** kernel to understand what *the host* does is a different thing and
is exactly the research carrick needs; nothing below derives a Linux syscall
semantic from a kernel source. Every load-bearing XNU claim is cited by
`file:line` against that tag. Host probes were compiled and run on this machine
(Apple M4, macOS 27.0 build 26A5388g); their source is preserved in the
scratchpad and the receipts are inline.

---

## 1. The XNU mechanism, established from source

### 1.1 The wall is one hardcoded check in the kernel Mach-O loader

`load_machfile()` in `bsd/kern/mach_loader.c` runs at every `execve`/
`posix_spawn`. After parsing the Mach-O it enforces page-zero:

```c
// bsd/kern/mach_loader.c:874-903  (xnu-12377.1.9)
boolean_t enforce_hard_pagezero = TRUE;                       // :700
...
if (enforce_hard_pagezero &&
    (vm_map_has_hard_pagezero(map, 0x1000) == FALSE)) {       // :874  generic 4 KiB floor
    ... return LOAD_BADMACHO;                                  // (with a 4K-compat exception, §1.3)
}
if (enforce_hard_pagezero && result->is_64bit_addr &&
    (header->cputype == CPU_TYPE_ARM64)) {                     // :897  arm64-only
    if (vm_map_has_hard_pagezero(map, 0x100000000) == FALSE) { // :899  demands a 4 GiB pagezero
        ... return LOAD_BADMACHO;                              // :901
    }
}
```

`vm_map_has_hard_pagezero(map, N)` is simply `map->min_offset >= N`
(`osfmk/vm/vm_map.c:21966`). So a 64-bit `CPU_TYPE_ARM64` main image **must** have
`min_offset >= 0x1_0000_0000` — a full 4 GiB reserved low range — or the load
returns `LOAD_BADMACHO`. `LOAD_BADMACHO` propagates to exec's `badtoolate:` path,
which does `psignal_with_reason(current_proc(), SIGKILL, …EXEC_EXIT_REASON_BAD_MACHO)`
(`bsd/kern/kern_exec.c:2285`, reason created at `:1487`). **This is the exact
SIGKILL the project probed on 2026-08-02** (`-pagezero_size 0x4000` main → killed
at exec). It is the *kernel Mach-O loader*, not dyld and not AMFI: the check is
in `load_machfile` before dyld runs and before any code-signing/entitlement gate,
and no entitlement is consulted by it.

**There is no arm64 bypass.** The only `enforce_hard_pagezero = FALSE` assignment
(`:849`) sits inside `#if __x86_64__` — i.e. it exists only in the kernel built
for Intel Macs, and even there only for 32-bit binaries. On Apple Silicon the
flag is unconditionally `TRUE` and the `CPU_TYPE_ARM64` branch is
unconditional. The `fourk_binary_compatibility_unsafe` relaxation (`:882`,
declared `:568`) requires `!is_64bit && !MH_PIE && page_size != 4K` — it never
matches a 64-bit arm64 image. Rung 5's "settled kernel policy" claim is correct
and I confirmed the precise code path it rests on.

### 1.2 The 4 GiB floor is a *map property fixed at exec*, and monotonic

`__PAGEZERO` is recognised in `load_segment()`: a segment at address 0, not file-
backed, raises the floor via `vm_map_raise_min_offset(map, vm_end)`
(`mach_loader.c:2413`; pagezero recognised and `pagezero_end` computed at `:1391`).
`vm_map_raise_min_offset` **rejects any attempt to lower** `min_offset`
(`vm_map.c:22025-22033`: `new_min_offset < map->min_offset → KERN_INVALID_ADDRESS`)
and rejects raising it over already-allocated space (`:22037 → KERN_NO_SPACE`).
There is no `lower_min_offset`. `fork()` copies the parent's `min_offset` into the
child map verbatim (`vm_map_fork` builds the new map with `old_map->min_offset`,
`vm_map.c:13826`). So the floor is (a) established once at exec from the Mach-O's
own `__PAGEZERO`, (b) permanent and one-way for the life of the map, (c)
inherited by fork. This decides the seed question "is the floor a map property or
a per-call check?": **both** — it is a map property (`map->min_offset`) *enforced
on every mapping call*.

### 1.3 Every low-mapping API re-checks `min_offset`; `deallocate` cannot help

`vm_map_enter()` computes `effective_min_offset = map->min_offset`
(`vm_map.c:2479`) and rejects `start < effective_min_offset` with
`KERN_INVALID_ADDRESS` (`:2549-2552`). Every fixed placement — `mmap(MAP_FIXED)`,
`mach_vm_allocate(VM_FLAGS_FIXED)`, `mach_vm_map`, `vm_remap` — funnels through
`vm_map_enter`, so all of them hit the same floor. `mach_vm_deallocate` of the
pagezero range "succeeds" (deallocating unmapped VA is a no-op) but leaves
`min_offset` untouched, which is why the project saw `KERN_SUCCESS` followed by
`mmap → MAP_FAILED` / `vm_remap → KERN_INVALID_ADDRESS`. Cross-process
(`task_for_pid` + `mach_vm_map` into the target) is validated against the
*target's* `min_offset`, so it fails identically. All of this is confirmed from
source and matches the earlier probes; I did not find a variant that survives.

### 1.4 The one architectural crack: the check keys on `CPU_TYPE_ARM64`

The 4 GiB demand at `:897` is gated on `header->cputype == CPU_TYPE_ARM64`. An
**x86_64** main image (`CPU_TYPE_X86_64`) never reaches that branch; it faces only
the generic `0x1000` floor at `:874`, which a `-pagezero_size 0x1000` link
satisfies. On Apple Silicon an x86_64 main runs under **Rosetta 2**
(`IMGPF_ROSETTA`, `load_rosetta()` at `mach_loader.c:3353`, mapping the Rosetta
runtime high near the shared-cache base). This is the mechanism behind the
Rosetta option; §4 measures what it actually buys.

---

## 2. New host probes (this session) — what Darwin actually allows

All built and run on this host; sources in the scratchpad
(`rosetta_lowva_probe.c`, `rosetta_lowva_map.c`, `rosetta_mach_floor.c`,
`rosetta_floor_bisect.c`, `highbase_probe.c`, `lowexec_probe.c`). No guest runs,
no Docker, no sudo.

1. **A small-pagezero x86_64 main runs under Rosetta and can map low.** Linked
   `-arch x86_64 -Wl,-pagezero_size,0x1000`, `__PAGEZERO` vmsize = `0x1000`
   (`otool` confirmed). It runs (translated) and `mmap(MAP_FIXED)` + write +
   **execute** succeed well below 4 GiB. `lowexec_probe` mapped `0x400000` RW,
   wrote `mov eax,42; ret`, flipped to RX, and the call returned 42.
2. **The reachable low floor tracks the main image, not a constant.** A naive
   powers-of-two scan first suggested a ~64 MiB floor, but `rosetta_floor_bisect`
   (three ASLR slides) showed the floor sitting a few pages above the main image
   base each time: image `0x741000`→floor `0x7c7000`; image `0x4943000`→floor
   `0x49c9000`; image `0xdaf000`→floor `0xe35000`. The "floor" is just the top of
   the image + dyld; the range *below* the image stayed reserved.
3. **Placing the image high frees the entire low 4 GiB.** `highbase_probe`,
   linked `-Wl,-no_pie -Wl,-segaddr,__TEXT,0x100000000` (image at 4 GiB,
   `slide=0`), mapped **`0x10000`, `0x400000`, `0x1000000`, `0x40000000` all
   successfully and writably** — Go's arm64 ET_EXEC base and the classic amd64
   base included. So a Rosetta process whose own Mach-O is linked high genuinely
   exposes the guest's native low addresses.
4. **HVF is unavailable from the Rosetta process (as-tested).** `hv_vm_create(0)`
   returned `0x4` (non-success) under Rosetta. *Caveat:* this probe binary was
   **not** codesigned with `com.apple.security.hypervisor`, so I cannot cleanly
   separate "Rosetta forbids HVF" from "missing entitlement." Either way HVF did
   not come up; §6.A explains why this makes the Rosetta+HVF combination moot
   regardless of which cause it is.
5. **`mach_vm_allocate(VM_FLAGS_FIXED)` at low VAs returns `KERN_INVALID_ADDRESS`
   even in the Rosetta process** while `mmap(MAP_FIXED)` succeeds at the same
   addresses once the image is high — the Mach trap path applies a stricter
   user-range check than the BSD `mmap` path. Not load-bearing for the verdict,
   recorded so the next investigator does not chase it.

---

## 3. Restating the question precisely, because it has three different answers

"ET_EXEC → direct" conflates three things the levers treat differently:

- **(Q-sw)** Can arm64 ET_EXEC run as **patched host-native process state** in a
  normal Darwin process (tier D's literal model: guest registers in physical
  registers, `svc`→island, no address translation)? — This is what rung 5
  answered.
- **(Q-bias)** Can we keep tier T's **biased address model** (guest at
  `bias+va`, so low VAs are never needed) but **drop the per-instruction
  translation** and instead *patch in place*? — The task's seed #5, the
  "sleeper."
- **(Q-hw)** Can arm64 ET_EXEC run **untranslated at its native low addresses**
  via some **hardware** address-translation layer other than the Darwin process
  map? — The HVF route.

Keeping these separate is the whole analysis: (Q-sw) and (Q-bias) are both **no**
in software, for *different* reasons; (Q-hw) is the only software-free escape and
it is not "on a Darwin process" at all.

---

## 4. The enumerated routes, costed

Ranked by whether they can plausibly move the **arm64 canonical lane** onto a
patch-not-translate path. Effort sizes are rough (S ≤ 1 wk of focused work, M ≤
1 month, L = quarter-plus), correctness risk is the guest-visible-divergence
exposure.

### Route A — HVF stage-1 "micro-vmm" (shared VM, per-process TTBR0) — **the only (Q-hw) escape for arm64**

**Mechanism.** One `hv_vm_create` VM for the whole container. Stage-2 identity-
maps a shared arena. Each guest *process* owns a host process (PID/FDs/signals
unchanged) and builds an ARMv8 **stage-1** page table in the arena mapping its
guest VAs (`0x10000`, `0x400000`, …) to arena IPAs. A small vCPU pool (≈ core
count) runs guest code at EL0; on `svc #0` the vCPU exits, the owning host
process reads the exit registers from a shared mailbox and dispatches through the
**existing `SyscallDispatcher`** with its own fd table. Guest code executes
**unmodified at its native low addresses** — no translation, no bias, no `svc`
patching (the `svc` traps to the hypervisor natively).

**What XNU/carrick say about it.** Feasible in principle and *mostly already
built*: carrick's VMM lane already constructs host stage-1 identity page tables
and enables `SCTLR_EL1.M` on an HVF vCPU running EL0 Linux code
(`carrick-mem/src/memory.rs` `stage1_identity_page_tables`, the marquee function;
HVF sysreg plumbing in `carrick-vmm-hvf/src/trap.rs`). The novel parts are
(i) *sharing one VM* across all guest processes with per-process `TTBR0_EL1` +
ASID instead of one-VM-per-process, which is what dodges the **measured 127-VM
HVF ceiling** (`project_hvf_residency_e4`, `admission_cap` notes), and (ii) the
cross-process **mailbox IPC** to hand register state between the syscall-owning
host process and the vCPU thread.

**Honest cost.** This **reintroduces a hypervisor** into the lane whose founding
premise was "no hypervisor at all" — it is best understood as a *third backend*
(a thin shared-VM VMM), not an extension of tier D. Its tax is a **VM-exit +
IPC round-trip per guest syscall**, replacing the native lane's in-process
~0.3 µs dispatch. That is the exact term the native lane was built to delete. For
**compute-bound** arm64 ET_EXEC it is pure win (translation and bias both gone,
syscalls rare). For **`go build`** — which the memory notes and the
direct-execution spec §5 both characterise as *process-creation- and syscall-
bound*, not translation-bound — per-syscall exits could **erase** the win; that
is the make-or-break unknown.

**Would it put arm64 `go build` on a patched path?** It removes translation for
the arm64 toolchain, yes — but by *hardware* execution, not patching, and only if
the per-syscall exit cost stays below what translation+bias cost per syscall.
**Effort L; correctness risk medium** (stage-1 PT construction, ASID/TLB
coherence across the mailbox handoff, fork COW of PT trees). **This is the top
recommendation to *investigate*, gated on one cheap measurement (§7).**

### Route B — patch-in-place while keeping the bias (Q-bias) — **refuted, but instructively**

The seductive idea: rung 1 (translation) is 63.8%/2.76x and rung 2 (bias) is only
13.6%; if we could keep the cheap bias and drop the expensive translation, we'd
capture most of the win on the low-VA lane without touching pagezero.

**Why it cannot work in software.** Software bias means adding `+bias` to *every*
guest memory access. A64 is fixed 4-byte; you cannot *insert* an `add`/rebias
before a load without shifting every following instruction, which breaks all
PC-relative offsets and branch targets — i.e. you must relocate into a larger
buffer, which **is** tier T. The one in-place trick — rewriting `ldr Xt,[Xn]` to
the register-offset form `ldr Xt,[Xn,x28]` with `x28`=bias — only covers accesses
that (a) have zero immediate offset and (b) have a register-offset encoding.
`LDP`/`STP` have **no** register-offset form at all; pre/post-index and non-zero
`#imm` forms have none either. So it patches a minority of accesses and the rest
still need translation, *and* it re-steals `x28` (Go's `g`), the exact cost the
direct-execution spec already flags. **Verdict: (Q-bias) is NO.** Translation
cost is *intrinsic* to software bias; you cannot separate rungs 1 and 2 in
software. **This is the sharpest new result in the paper** and it means the
"sleeper" is empty: the only way to have biased addressing without per-access
translation is *hardware* translation — which is Route A. **Effort n/a
(refuted).**

### Route C — load-time relocation of ET_EXEC to a high base (Q-sw via rebasing)

Map the guest high (like PIE) and fix up its absolute references so it runs in
tier D with **zero** bias and **zero** translation — the best possible outcome if
it were sound.

- **Generic ET_EXEC: unsound.** No relocation records. AArch64 *text* is PC-
  relative (ADRP/ADD) and would tolerate rebasing, but *data* holds absolute
  link-time pointers (jump tables, vtables, initialised function pointers) that
  are undiscoverable in general — identifying every absolute pointer without
  records is undecidable. A missed pointer is silent corruption. Matches rung 5
  point #2 and proposed-plan 5.4/6.8.
- **Go-specific relocation: possible, high-risk, narrow.** Go's linker emits a
  documented `moduledata`/`pclntab`/`typelink`/`itablink` layout (Go BSD-licensed,
  readable). A Go-aware pass could rebase the discoverable pointer tables. But
  (i) completeness is still unprovable — Go's GC scans stacks/heap using type
  metadata and *any* mis-relocated pointer base corrupts the heap; (ii) it is
  version-fragile (internal layout changes across Go releases); (iii) it violates
  the *unmodified-binary* premise in spirit even done at load time; (iv) it is
  Go-only (C/Rust static ET_EXEC get nothing). **Effort L, correctness risk very
  high.** A parallel-oracle harness (run biased tier T and relocated tier D on the
  conformance corpus, diff every result) is the only way to make it even
  arguably safe, and a single silent divergence class kills it. **Not
  recommended** except as a research spike if Route A's syscall tax proves fatal
  and a compute-heavy Go ET_EXEC workload actually matters.

### Route D — Rosetta x86_64 address space (the §1.4 crack) — **real, amd64-only, not a win for arm64**

**Mechanism (proven in §2).** A carrick "trampoline" main linked as x86_64 with a
`0x1000` pagezero and its own image based high runs under Rosetta and exposes the
full low 4 GiB. Map an **amd64** Linux ET_EXEC guest at its native `0x400000`;
Rosetta translates the guest's x86 instructions; carrick intercepts syscalls.

**Why it does not rescue the arm64 lane.** The process is x86_64: it cannot
execute **arm64** guest code natively (Rosetta forbids mixing native arm64 and
translated x86 in one process), and it cannot host an HVF VM (§2 probe 4; and
even if it could, an HVF guest runs in stage-2 and would not need Rosetta's low
VA at all — so Rosetta+HVF is incoherent, killing proposed-plan 6.3a on
architecture grounds, not just the entitlement question). So Route D only serves
**amd64** guests, and for them it **replaces carrick's translation with Rosetta's
translation** — it is a *different translator*, not direct execution. carrick
already has an amd64 story via in-guest Rosetta on the VMM lane
(`docs/rosetta.md`); a userspace-Rosetta amd64 native lane is a genuinely new and
possibly attractive option for the amd64 `go build` lane (Rosetta's AOT is
excellent, and the guest runs at its true addresses so there is no bias), but it
needs an x86_64 build of carrick's dispatcher or an IPC split, and it is
**orthogonal to the arm64 canonical lane the ablation ladder is about.**
**Effort M, correctness risk medium (two-translator syscall/signal seams).
Recommended to log as the amd64-lane option; does not answer the arm64
question.**

### Route E — build the guest PIE (upstream / opt-in) — trivial, out of scope by premise

`go build -buildmode=pie` yields ET_DYN that already runs in tier D at zero
overhead (rung 1's measured direct arm). Zero cost, Go-only, and — as a *user*
action — fine to document. But carrick must run **unmodified** binaries, so this
is not a carrick capability; and having carrick silently rebuild the guest as PIE
inside the container is Route C's relocation problem wearing a compiler
(and only works when the guest's full source/toolchain is present). **Document as
guidance; not a runtime route.** Matches proposed-plan 6.5.

### Route F — fault-and-fixup at native low VAs — dead

Even if we could map guest memory at bias and trap every access via a Mach
exception handler to emulate it (proposed-plan 5.6), it is orders of magnitude
slower than software bias and cannot map the *absolute* low addresses anyway
(§1.3). Dead, agreeing with the prior analysis.

### Route G — kernel extension / custom `vm_map` — dead

A kext could `vm_map_create` a task with `min_offset = 0x1000`, but SIP blocks
third-party kexts on modern macOS and Apple is removing kext capability; DriverKit
runs in userspace with no `vm_map` access. Unshippable. Agrees with proposed-plan
6.6.

---

## 5. Where I agree and disagree with `proposed-plan.md` (and the missing review)

I could **not locate `proposed-plan-review.md`** — it is not in the working tree,
not tracked in git, not in any stash, and a filesystem search found nothing. I
reviewed `proposed-plan.md` (repo root) directly and adjudicate it here; if the
review doc resurfaces, this section is the place to reconcile.

**Agree with the plan:**
- 5.1–5.5, 6.6, 6.8, 6.9 are correctly refuted; I re-derived 5.1/5.2 from XNU
  source and they hold.
- 6.1b (the "VM-server micro-hypervisor") is the strongest candidate — it is my
  Route A, and I agree it is the one worth measuring. Its cost model (per-syscall
  IPC ≪ per-instruction translation) is *directionally* right **for compute**.

**Disagree / sharpen:**
- The plan's 6.1b cost model quietly assumes the workload is translation-bound.
  For the **canonical `go build`** it is not — it is process/syscall-bound, so the
  per-syscall **VM-exit + IPC** term the plan waves away as "negligible" is
  precisely the term that could sink it. The plan never confronts that the native
  lane's entire syscall advantage (in-process ~0.3 µs, no exit) is *given back* by
  this design. My §7 makes that the gating measurement.
- The plan's §2 enforcement-chain sketch (`vm_map_raise_min_offset` "monotonic")
  is right in spirit but slightly off in the arm64 detail: the 4 GiB demand is a
  **separate hard check** in `load_machfile` (`:897-903`), not a consequence of
  `raise_min_offset`; `raise_min_offset` is how the floor gets *set* from
  `__PAGEZERO`, the 4 GiB *minimum* is asserted independently. Minor, but it
  matters for anyone hunting a bypass.
- 6.3a (Rosetta + HVF) is presented as "best candidate, needs empirical test."
  I tested it: HVF did not come up in a Rosetta process, **and** the combination
  is architecturally pointless even if it did (an HVF guest needs no host low VA).
  Downgrade 6.3a from "investigate" to **incoherent**.
- 6.3c (Rosetta + x86 guest) the plan rates "medium." I'd **raise** its standing
  as an *amd64-lane* option specifically — the §2 probes prove the address space
  works and low-VA execution works — while stressing it is **irrelevant to the
  arm64 canonical lane**, which the plan does not make explicit.
- The plan omits my Route B refutation entirely (patch-in-place-with-bias). That
  refutation is important because it proves the ablation ladder's rungs 1 and 2
  are **not** independently harvestable in software — a conclusion the plan's
  framing ("25% bias tax," "translation overhead") leaves open.

---

## 6. Verdict on rung 5's NO

**UPHELD and NARROWED.**

- **Upheld** for its literal claim (Q-sw): arm64 ET_EXEC **cannot** run as patched
  host-native process state on a normal Darwin process. The 4 GiB `__PAGEZERO`
  floor is a hardcoded, entitlement-free, arm64-specific kernel-loader check
  (`mach_loader.c:897`), set once at exec and monotonic (`vm_map.c:22025`),
  enforced on every mapping call (`vm_map.c:2549`); relocation without records is
  unsound. I verified the exact SIGKILL path and found no surviving variant. Both
  of rung 5's pillars are correct.
- **Narrowed** because rung 5's framing ("the translation lever stays
  PIE-lane-only … canonical-lane work should go to the per-op program") is *too
  strong* as stated. Two escapes exist that rung 5 did not enumerate:
  1. **(Q-hw) Route A** removes translation *and* bias for arm64 low-VA guests via
     an HVF stage-1 micro-vmm — not on a Darwin process map, and at a per-syscall
     exit cost, but a real architecture that carrick is 80% wired for.
  2. **(Q-bias) is impossible in software** — and this *strengthens* rung 5's
     spirit: it proves the only way off translation for a low-VA guest is
     hardware translation, i.e. Route A. Rung 5 was right that software has no
     path; it just did not name the hardware one.
  3. The **Rosetta crack (Route D)** is real for amd64 guests, absent from rung 5.
- **Net:** for the **arm64 `go build`** lane the practical answer remains **NO to
  a patched path** and **MAYBE to a hardware path** (Route A), decided by one
  measurement. Rung 5's downstream recommendation — put canonical-lane effort
  into the per-op amplification program — stands, *unless* Route A's decisive
  experiment comes back favourable.

---

## 7. Recommendation and the cheapest decisive experiment

**Top recommendation: measure Route A's gate before designing anything.** Route A
is the only route that (a) removes both translation and bias for the arm64
canonical lane and (b) is mostly already built in carrick's VMM crates. But it
trades the native lane's zero-exit syscalls for VM-exit+IPC, and the canonical
lane is syscall/process-bound — so the whole route lives or dies on one number.

**The decisive experiment (Effort S, ~1 day, no new architecture):**
1. Create one HVF VM + one vCPU (carrick already does this in the VMM lane).
2. Map a single code page containing `svc #0` in a tight loop at EL0 with a
   **host-built stage-1 page table** and `TTBR0_EL1`/`TCR_EL1`/`SCTLR_EL1.M`
   set by `hv_vcpu_set_sys_reg` — reusing `stage1_identity_page_tables`. This
   simultaneously proves host-built stage-1 PTs drive an EL0 guest (the second
   open question) and times the loop.
3. Measure **`hv_vcpu_run` round-trip per `svc` exit**, plus the **mailbox IPC
   round-trip** (`__ulock_wake`/`__ulock_wait` between two processes) separately.
4. Multiply by the **measured `go build` syscall count** under carrick (already
   obtainable from the amplification-ledger tooling) and compare against the
   translation+bias CPU the same build spends today.

**Kill/keep rule:** if `(exit + IPC) × syscalls` for the real `go build`
exceeds the translation+bias CPU it would remove, **Route A is dead for the build
lane** (keep it only for a hypothetical compute-bound arm64 ET_EXEC workload, of
which the corpus has none) and rung 5's NO becomes effectively final for the
canonical lane — redirect to the per-op amplification program exactly as rung 5
says. If it is comfortably under, Route A graduates to a full design and becomes
the first credible multiple-sized lever the arm64 build lane has ever had.

**Second, independently: log Route D as the amd64-lane option** with the §2
receipts, since it is proven-real and costs nothing to record; it is not on the
arm64 critical path.

---

## 8. What I could not determine

- **Route A's syscall-tax verdict** — the one number that decides everything —
  was **out of scope** here (design/research only; the measurement needs HVF glue
  wired to a stage-1 loop). §7 is that experiment.
- **Whether HVF is forbidden *because* of Rosetta or merely because my probe
  lacked the hypervisor entitlement.** The probe was not codesigned; I could not
  separate the two. It does not change Route D's verdict (Rosetta+HVF is
  incoherent regardless) but it is an honest loose end.
- **The exact reason `mach_vm_allocate(FIXED)` rejects low VAs where
  `mmap(MAP_FIXED)` succeeds** in the high-based Rosetta process (§2 probe 5).
  Likely the Mach user-range sanitiser vs the BSD mmap overwrite path, but I did
  not trace it to a line; it is not load-bearing.
- **Go-specific relocation completeness (Route C)** is unprovable by construction;
  I did not attempt to bound the residual absolute-pointer classes, because a
  single silent class is disqualifying and the parallel-oracle cost is high.
- The **missing `proposed-plan-review.md`** — I adjudicated `proposed-plan.md`
  directly (§5); if the review existed it may have raised points I could not see.

---

## 9. Receipts

- XNU: `apple-oss-distributions/xnu` @ `xnu-12377.1.9`. Cited lines:
  `bsd/kern/mach_loader.c:700,849,874-903,1391-1392,2413`;
  `bsd/kern/kern_exec.c:1487,2285`;
  `osfmk/vm/vm_map.c:2479,2549-2552,13826,21966,22025-22037,24603`.
- carrick: `crates/carrick-dsr/src/address.rs:23,519-523`;
  `crates/carrick-native-darwin/src/direct.rs:1137-1145,1272-1275`;
  `crates/carrick-mem/src/memory.rs` (`stage1_identity_page_tables`);
  `crates/carrick-vmm-hvf/src/trap.rs`.
- Host probes (scratchpad, this host, macOS 27.0 / Apple M4):
  `rosetta_lowva_probe.c` (small pagezero runs, low map/exec ok),
  `rosetta_floor_bisect.c` (floor tracks image base across 3 ASLR slides:
  `0x741000→0x7c7000`, `0x4943000→0x49c9000`, `0xdaf000→0xe35000`),
  `highbase_probe.c` (`__TEXT`@`0x1_0000_0000`, slide 0 → `0x10000`/`0x400000`/
  `0x1000000`/`0x40000000` all map), `lowexec_probe.c` (exec at `0x400000`
  returns 42; `hv_vm_create`→`0x4`), `rosetta_mach_floor.c`
  (`mach_vm_allocate FIXED` low → `KERN_INVALID_ADDRESS`).
- Prior art reconciled: `docs/perf-results/2026-08-07-ablation-ladder.md` (rung 5),
  `docs/superpowers/specs/2026-08-02-direct-execution-tier-design.md` (§3 probes),
  `docs/superpowers/specs/2026-08-02-performance-roadmap.md` §5 (rejected
  alternatives — the "general identity mapping structurally excluded" reasoning is
  confirmed against XNU here), `proposed-plan.md` (§5 adjudication).
