# Rosetta + binfmt_misc: how carrick invokes Rosetta, and how to do it "more correctly"

*Status: research / design notes (2026-06-07). Clean-room — derived from man-pages,
the System V x86-64 ABI, Docker's observable behavior, and the `rosetta` binary's
own strings/observed behavior. **No Linux kernel source was read.***

## TL;DR

carrick currently runs x86_64 Linux binaries by a **userspace binfmt_misc
emulation**: it loads Apple's static `rosetta` interpreter as the guest image and
lets Rosetta open+map the target itself ("standalone" mode, `rosetta <elf>`). The
auxv carrick hands Rosetta therefore describes *rosetta* (a static ET_EXEC), not
the x86 target. Rosetta builds the inner x86 auxv by **forwarding its own
`/proc/self/auxv` as a template**, overwriting the arch/target-specific entries.
The 2026-06-07 fix (`fix(rosetta): supply AT_BASE …`) added `AT_BASE` to that
template for dynamic targets so Rosetta emits it for the inner auxv (it had been
dropping it, breaking musl's dynamic linker).

Post-fix, carrick's inner x86 auxv is **byte-for-meaning identical to Docker
Desktop's** (verified via `LD_SHOW_AUXV=1`). The remaining "incorrectness" is
*architectural*, not behavioral: we rely on Rosetta overwriting a placeholder
`AT_BASE`, and Rosetta (not carrick) does the x86 ELF loading. A "more correct"
implementation makes carrick behave like the kernel's binfmt+ELF-exec path.

## 1. How real binfmt_misc works (man-page / spec level)

A binfmt_misc registration is `:name:type:offset:magic:mask:interpreter:flags`.
The `flags` are capital letters; the four that matter here
([kernel.org admin-guide](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html),
[Wikipedia](https://en.wikipedia.org/wiki/Binfmt_misc)):

| flag | meaning |
|------|---------|
| **P** | *Preserve argv[0].* Interpreter is run with `argv = [interp, <target full path>, <orig argv[0]>, <orig args…>]`. Without P the kernel clobbers argv[0] with the target path. |
| **O** | *Open binary.* The kernel opens the target and passes the **fd** (not the path) to the interpreter. |
| **C** | *Credentials.* Compute the new process's creds/security token from the **target**, not the interpreter. Implies **O**. |
| **F** | *Fix binary.* Open the interpreter at *registration* time and spawn from that fd, so it survives mount-namespace / filesystem changes. |

**Docker Desktop registers Rosetta as `POCF`** with interpreter `/mnt/rosetta`
(magic/mask = the ELF64 LE x86_64 signature). So in Docker, Rosetta is handed the
target as an **open fd**, with credentials from the target, and the kernel pins
the `rosetta` image at registration.

Crucially — and this is the part that determines the auxv — the **kernel loads
the x86 target (and its `PT_INTERP`) as a normal ELF and builds the auxv
describing the *target*** (`AT_PHDR`/`AT_ENTRY` = target, `AT_BASE` = the target's
dynamic linker base), *then* runs the registered interpreter (rosetta) over it.
We can't read the kernel source to confirm the exact mechanism, but the auxv
Rosetta ends up seeing (below) is unambiguously a *target-describing* auxv with
`AT_BASE`, which is the observable contract we must reproduce.

## 2. The Rosetta contract (observed)

From `strings` on `/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta` and live
experiments:

- `Usage: rosetta <x86_64 ELF to run>` — the **standalone** launcher form carrick uses.
- `gStackAuxv != nullptr`, `/proc/self/auxv`, `/proc/thread-self/auxv`,
  `open_auxv_tmp`, `auxv_fd` — **Rosetta reads its own auxv** (stack first, with
  `/proc/self/auxv` as the file form) and uses it as the **template** for the
  inner x86 auxv it builds for the translated program.
- `get_argv_skip_for_other_rosetta` — Rosetta tolerates several argv shapes
  (incl. nested-rosetta), which is why carrick's non-binfmt argv ordering works.
- It reads `/proc/sys/vm/mmap_min_addr`, `/proc/sys/kernel/randomize_va_space`,
  `/proc/self/exe`, `/proc/self/maps`, `/proc/self/cmdline`.
- `rosetta` itself is a **static `ET_EXEC` aarch64** binary (`e_type=2`,
  `e_machine=0xb7`) — so it legitimately has no `AT_BASE` of its own.

**How Rosetta transforms the template auxv → inner x86 auxv** (measured by
diffing carrick's outer auxv against the x86 program's `/proc/self/auxv` and
Docker's):

| entry | Rosetta's handling |
|-------|--------------------|
| `AT_PHDR`, `AT_PHENT`, `AT_PHNUM` | **overwritten** with the target's values |
| `AT_ENTRY` | **overwritten** with the target's entry |
| `AT_BASE` | **overwritten** with the real ld-musl/ld-linux base it maps — **but only emitted if the template already has an `AT_BASE` slot** ← *this was the bug* |
| `AT_HWCAP` | **overwritten** with the x86 value (`0xf8b8b15`); carrick's aarch64 `0x1fb` is discarded |
| `AT_PLATFORM` | **overwritten** → string `"x86_64"` (re-pointed into the new stack) |
| `AT_EXECFN`, `AT_RANDOM` | forwarded, re-pointed into the new stack |
| `AT_SYSINFO_EHDR` (vDSO) | **stripped** (becomes `AT_IGNORE`) — x86 gets no vDSO |
| `AT_CLKTCK`, `AT_SECURE`, `AT_UID/EUID/GID/EGID`, `AT_PAGESZ`, `AT_FLAGS`, `AT_HWCAP2` | **forwarded as-is** |

So Rosetta gets the arch-specific entries right *by itself*; the only thing it
will not invent is the **presence** of `AT_BASE`.

## 3. carrick's current model and why it works

`maybe_redirect_to_rosetta` (runtime.rs) detects an x86_64 target, loads the
static `rosetta` ELF as the guest image, and builds
`argv = [orig argv[0], target_path, orig args…]`. Rosetta then opens+maps the
target and its `PT_INTERP` itself (we see the reserve→`MAP_FIXED` overlay dance,
plus a negative-address `MAP_FIXED_NOREPLACE` probe, in the syscall trace).

Because carrick's image is the *static* rosetta, `linux_auxv_from_load_plan`
emits no `AT_BASE`. The fix adds one for **dynamic** targets
(`with_auxv_base(ROSETTA_AT_BASE_PLACEHOLDER)`); the value is a placeholder
Rosetta overwrites. Result (verified `LD_SHOW_AUXV=1`, carrick vs Docker, same
glibc binary): identical `AT_BASE`, `AT_PHDR`, `AT_ENTRY`, `AT_PLATFORM=x86_64`,
`AT_HWCAP`, `AT_EXECFN`, `AT_SECURE`.

### What's still not "correct"

1. **Reliance on the AT_BASE override.** We hand Rosetta a *wrong* `AT_BASE` and
   trust it to replace the value. Proven on this Rosetta build (Apr 2026); a
   future Rosetta that instead *trusts* the template value would mis-place the
   dynamic linker.
2. **Rosetta does the ELF loading.** The target/`PT_INTERP` mapping happens via
   Rosetta's mmap pattern, so carrick's mmap emulation must keep supporting the
   high-VA alias arena, `MAP_FIXED_NOREPLACE` at negative addresses, and the
   reserve+overlay sequence — a larger emulation surface than carrick's own
   (well-tested) ELF loader needs.
3. **argv shape is not the binfmt-P shape.** It works via
   `get_argv_skip_for_other_rosetta`, another reverse-engineered dependency.

## 4. A "more correct" binfmt — Option A (carrick acts as the kernel)

Reproduce the Docker contract: have **carrick** load the x86 program the way the
kernel does, and hand Rosetta a complete *target-describing* auxv.

Steps:
1. **Map the x86 target ELF** via carrick's `AddressSpace` loader (it already
   handles ET_DYN load-bias and `PT_INTERP`). The loader is arch-agnostic for
   placement — it just writes segment bytes at guest VAs; Rosetta (aarch64) reads
   them. (`inspect_elf_bytes` already classifies `Machine::X86_64`; only the
   `run-elf` *static* path rejects machine 62 today.)
2. **Map the target's `PT_INTERP`** (ld-musl / ld-linux) at a high base; record
   that base.
3. **Build a complete x86 auxv describing the target**: `AT_PHDR`/`AT_PHENT`/
   `AT_PHNUM` (target), `AT_ENTRY` (target), **real** `AT_BASE` (interp base),
   `AT_EXECFN` (target path), `AT_RANDOM` (16 bytes), `AT_PAGESZ`, `AT_PLATFORM`
   `"x86_64"`, `AT_HWCAP` (x86), `AT_CLKTCK`, uid/gid, `AT_SECURE`, `AT_FLAGS`,
   **no `AT_SYSINFO_EHDR`**.
4. **Load `rosetta`** and run it with that stack/auxv, so its `/proc/self/auxv`
   (which carrick already serves from `linux_auxv_image`) and its stack auxv both
   describe the target — exactly what the Docker kernel produces.

Pros: real `AT_BASE` (no override reliance); ELF loading via carrick's tested
loader; the auxv we provide *is* the kernel contract (smallest reverse-engineered
surface). Rosetta's per-entry overwrite still corrects anything arch-specific, so
we're robust even if we get an x86 detail slightly wrong.

### Open risks (must be settled by experiment before committing)

- **Does Rosetta enter a no-reload "binfmt mode" from the auxv alone?** In
  standalone mode it loads the target itself. If carrick pre-maps the target
  *and* Rosetta still re-maps it (because it keys off the argv target path, not
  the auxv), we get a double-map / conflict. Need to find Rosetta's trigger:
  likely "target already mapped at `AT_ENTRY`/`AT_PHDR`, and no ELF path in
  argv" → translate in place. **Experiment:** pre-map a target + a
  target-describing auxv, invoke rosetta with an argv that has *no* ELF path (or
  the binfmt-P shape), and check whether it runs without re-mapping.
- **The O-flag fd.** Docker passes the target as an open fd. If Rosetta needs the
  fd to (re)read target bytes rather than reading the mapped pages, carrick must
  pass one (e.g. via `/proc/self/fd/N` or an argv fd). Determine whether mapped
  pages suffice.
- **Cost.** carrick must replicate the kernel's x86 ELF exec faithfully (PIE
  base / ASLR policy, GNU_RELRO, bss zero-fill, the SysV initial-stack layout for
  x86). More code than the current ~30-line redirect.

### Linchpin experiment result (2026-06-07): Option A is INFEASIBLE for Rosetta

Prototyped Option A behind `CARRICK_BINFMT_FAITHFUL`: carrick mapped the x86
target + its `PT_INTERP`, built a target-describing auxv, overlaid the rosetta
image, and entered at rosetta's entry — with `argv` = the *program's* argv (no
ELF path), the way a kernel-pre-loaded program looks. Result:

```
rosetta error: failed to open elf at -m
```

Rosetta started (faulted in its own text at `0x800000088d14`) and tried to
**`open(argv[1])` as the ELF to translate** (`argv[1]` was `-m`). So:

> **Rosetta always loads the target itself from `argv[1]` (the standalone
> `Usage: rosetta <elf>` contract). It does NOT consume a pre-mapped target.**

Therefore carrick cannot "act as the kernel, map everything, and have Rosetta
translate in place." Pre-mapping is at best ignored (Rosetta re-`open`s and
re-maps at addresses *it* chooses) and at worst a double-map conflict. And since
Rosetta picks the target/interp load addresses itself, it **must** overwrite
`AT_PHDR`/`AT_ENTRY`/`AT_BASE` regardless — so even a "real" `AT_BASE` carrick
computed would be discarded. The placeholder-`AT_BASE` (committed fix) is not a
hack to remove; it is the *correct* way to interface with Rosetta's
auxv-forwarding when Rosetta owns the load.

A possible (untested) exception is the binfmt **O** flag: Docker passes the
target as an *fd* and the kernel pre-maps it, and Rosetta references
`/proc/self/fd/%d` in its strings. Whether the fd path makes Rosetta reuse a
pre-mapping (vs re-`open`) is unverified and would need a separate experiment.
Given the path-mode result, it is not pursued here.

**Consequence for "faithful binfmt":** it cannot mean "carrick provides the
mapping." It means a faithful *mechanism*: a binfmt_misc registry, flag-driven
argv/fd/creds, and a redirect transparent to the program (`/proc/self/exe` =
target — carrick currently mis-reports the interpreter — clean argv, target
auxv). The auxv-template + `AT_BASE` slot approach stays, because that is how
Rosetta actually consumes the auxv.

## 5. Option B — harden the standalone model (incremental, low-risk)

Keep the current model but defend the one fragile assumption:

- **Add a conformance probe** that boots the same x86 binary under carrick and
  under Docker's Rosetta and asserts **auxv parity** (`LD_SHOW_AUXV=1` diff:
  `AT_BASE` present + every forwarded entry equal). This catches a future Rosetta
  that stops overwriting the placeholder, or any forwarded-entry drift — the
  exact failure classes the placeholder approach is exposed to.
- Keep the placeholder, documented as Rosetta-overwritten.

## 6. Recommendation

The post-fix auxv already matches Docker, so **Option B first** (cheap insurance:
the Docker-vs-carrick auxv-parity probe). Pursue **Option A** as a separate,
flag-gated effort *iff* we want to (a) stop relying on the AT_BASE override or
(b) move x86 ELF loading off Rosetta and onto carrick's loader — and only after
the "does Rosetta translate a pre-mapped target without re-loading" experiment
confirms the binfmt-mode trigger. Until that experiment passes, Option A is a
rewrite resting on an unverified assumption; Option B is correct *and* verified.
