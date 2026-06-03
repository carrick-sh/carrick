# Rosetta glibc `linux/amd64` — land + broaden (design spec)

Status: design for **finishing** the unmerged TTBR1/JIT layer that makes
unmodified `linux/amd64` (x86-64) container images run under Apple Rosetta 2, then
broadening it from the `uname -m` proof to flagship glibc workloads. The work lands
on a new branch `feat/rosetta-glibc-amd64` off current `main`.

## Background — what is already on `main` vs. what is not

The Rosetta integration was built in two layers across the branch lineage
`feat/rosetta-amd64` → `feat/rosetta-ttbr1`:

- **`feat/rosetta-amd64` is fully merged into `main`** (0 commits ahead). This is the
  *base*: `Platform` enum + `--platform` flag, per-platform image cache, Rosetta ELF
  redirection (`maybe_redirect_to_rosetta`, binfmt-style argv), the licence/info
  **ioctl handshake** (`rosetta_handshake_ioctl`, `dispatch/mod.rs:2102`, called from
  `dispatch/fs.rs:2636`), the **TSO** path (`prctl` `PR_*_MEM_MODEL` →
  `DispatchOutcome::SetMemoryModel` → `ACTLR_EL1.EnTSO`), the high-VA→low-IPA
  `DispatchOutcome::MapHostAlias` / `map_host_alias` / `PageTableManager::map_aliased`
  subsystem, the vDSO `SHT_DYNSYM` section table, and `/proc/self/exe` resolution.
  `main` boots **TTBR0-only** (`TCR_EL1_BOOTSTRAP` at `carrick-hvf/src/trap.rs`,
  `EPD1=1`), and `main`'s own `docs/rosetta.md` still lists **"TTBR1/upper-half
  support" as the next architectural step** — i.e. the next layer was never landed.

- **`feat/rosetta-ttbr1` carries the unmerged next layer** — 8 commits on top of the
  base, but **396 commits behind `main`**. On that branch, x86-64 **glibc-dynamic**
  binaries run end-to-end: the validated demo is
  `carrick run --platform linux/amd64 --fs host debian:stable /bin/uname -m` →
  `x86_64`, exit 0, **209 translated syscalls**. That capability is what we are
  landing and broadening.

### The 8 commits (`feat/rosetta-amd64..feat/rosetta-ttbr1`)

| SHA | Kind | Disposition |
| --- | --- | --- |
| `e168597` | TTBR1 + EL0 ID-regs + IC IVAU/DC ZVA + `getrlimit(163)` | **re-port (core)** |
| `1d9bc11` | 16-bit pointer-tag strip + DC ZVA | **re-port** |
| `ef37588` | `rt_sigframe` layout + `esr_context` + `rt_tgsigqueueinfo(240)` | **re-port, minus 240** |
| `bb28946` | `uname` reports `x86_64` for Rosetta guests | **re-port (clean add)** |
| `0057b5c` | clear `no_access` on high-VA mmap overlay (a real bug) | **re-port if not already on `main`** |
| `51977f6`, `b982dd1` | docs | rewrite, do not replay |
| `d91ddd6` | demo asserts Alpine static-PIE exit 139 | fold into conformance lane |

## Why this is a re-port, not a merge/rebase/cherry-pick

`main` structurally moved the ground under the branch:

- **`trap.rs` was renamed** `carrick-runtime/src/trap.rs` → **`carrick-hvf/src/trap.rs`**
  (~77% similarity) **and rewritten** (+831/−136). All TTBR1/SCTLR/ID-reg work lands
  here; a 3-way merge keyed on the old path sees a delete/modify conflict.
- **`PageTableManager` moved** into the new **`carrick-mem`** crate
  (`carrick-mem/src/page_table.rs`); `map_aliased` lives there now.
- **The signal subsystem was rewritten on `main`** (+927 lines) *around the old
  `CarrickSigframe` layout* that this work needs to change.
- **`rt_tgsigqueueinfo(240)` already exists on `main`** — replaying the branch's add
  would be a duplicate match arm. `getrlimit(163)` and `carrick_x86_64` do **not**
  exist on `main` and add cleanly.

**Method (confirmed): hand re-port the *intent*, commit-by-commit, TDD-guided.** Read
each code commit, re-apply its intent into today's `carrick-hvf` / `carrick-mem` /
`dispatch`, write a failing test first where feasible, and reference the original SHA
in each new commit for provenance. `git cherry-pick`/merge are rejected — the rename +
signal rewrite make textual application meaningless.

## Non-goals

- **Static-PIE musl (Alpine).** It faults *inside Apple's Rosetta translator* (a
  static-PIE self-relocation reads back 0 → SIGSEGV → exit 139), verified by fault
  decode; Docker Desktop's Rosetta backend hits the identical fault
  (`docker/for-mac#6773`). Not fixable from carrick. Documented limitation only;
  glibc images are the supported path.
- No change to the native arm64 path. The Rosetta-only system-register and
  pointer-strip changes must remain no-ops for top-byte-zero (native) guests, and the
  arm64 demo (`… --platform linux/arm64 … uname -m` → `aarch64`) must stay green.

## Part 1 — Re-port the unlanded core onto `main`

Each item names the merged-`main` anchor it must reconcile against. Exact line numbers
will have drifted; treat them as starting points.

1. **TTBR1 / upper-half translation.** In `carrick-hvf/src/trap.rs`, change the
   rewritten `TCR_EL1_BOOTSTRAP` from TTBR0-only to enable TTBR1 (`EPD1` 1→0, `T1SZ=16`,
   `IRGN1/ORGN1/SH1=0b11`, `TG1=0b10` (4 KiB — note TG1 ≠ TG0 encoding), `IPS=0b010`,
   `TBI0`/`TBI1`), and set `TTBR1_EL1` to the **same** `pt_base` as `TTBR0_EL1` (shared
   root; lower-half mappings and upper-half alias projections occupy disjoint L0 slots).
   Apply to **both** bring-up sites (`map_address_space` and the execve replace path).
   In `carrick-mem/src/page_table.rs`, project x86-64 high-half VAs (`bits 55:48` all 1)
   through the existing `map_aliased` / `MapHostAlias` arena.
2. **EL0 ID-register MRS emulation + SCTLR.** In `carrick-hvf/src/trap.rs`, intercept a
   trapped EL0 `MRS` in the `CRn==0 / Op0==3 / Op1==0` feature-ID space and return the
   live vCPU value for `MIDR`/`ID_AA64{PFR,DFR,ISAR,MMFR}*` (RES0 for other `CRn==0`
   slots), advancing `ELR` by 4. Set `SCTLR_EL1` `UCI`(26)/`UCT`(15)/`DZE`(14) so EL0 `IC
   IVAU` / `DC CVAU/CVAC`, `CTR_EL0` reads, and `DC ZVA` do not trap.
3. **16-bit pointer-tag strip.** `strip_pointer_tag(a) = a & 0x0000_FFFF_FFFF_FFFF`
   applied in the syscall-arg mapping paths (`mapping_for_range`/`_mut`) and to the
   `mmap` address hint in `dispatch/mem.rs`, so Rosetta's tagged pointers (e.g. the RWX
   `ExecutableHeap` hint) resolve to their 48-bit backing region. Must be a no-op for
   top-byte-zero guests.
4. **`rt_sigframe` layout + `esr_context`.** In `carrick-abi/src/lib.rs`, reorder
   `CarrickSigframe` so `siginfo` (offset 0) + `ucontext` come first (Rosetta's
   trampoline does `mov x1, sp`); carrick's private rt_sigreturn fields move after.
   In `carrick-hvf/src/trap.rs` `inject_signal`, write a Linux `esr_context` record
   (magic `0x45535201`, size 16, the stashed `last_fault_esr`) into
   `uc_mcontext.__reserved` after the fpsimd record, bounds-checked. **Reconcile against
   `main`'s rewritten signal subsystem** — this is the second hard reconciliation. Skip
   `rt_tgsigqueueinfo(240)` (already on `main`; verify equivalence).
5. **`uname` → x86_64 + `getrlimit(163)`.** Add `LinuxUtsname::carrick_x86_64()` in
   `carrick-abi`; select it in `dispatch/proc.rs` `uname()` when the loaded executable is
   the Rosetta interpreter (else `carrick_aarch64()`). Add `getrlimit(163)` sharing
   `prlimit64`'s limits via the `rlimit_for_resource` helper.
6. **High-VA mmap `no_access` overlay fix** (`0057b5c`). Confirm whether `main` already
   carries the `set_no_access` call on the `MapHostAlias` path in `dispatch/mem.rs`
   (it post-dates the base); apply if missing. Prevents spurious syscall-path `EFAULT`
   on guest buffers (e.g. `getrandom` output) in a high-VA region overlaying a
   `PROT_NONE` reservation.

**Gate for Part 1:** clean codesigned `just build` from `feat/rosetta-glibc-amd64`,
no-panic clippy gate green, and `debian:stable /bin/uname -m` → `x86_64` (the proven
209-syscall demo) reproduced on this branch.

## Part 2 — Bring-up ladder to flagship workloads

Target bar (confirmed): **match the arm64 flagships under amd64** — `apt-get install`
on a Debian/Ubuntu glibc image and `python3 -m http.server`, end-to-end. Climb in
rungs; each rung is gated by a real codesigned run + the no-panic gate, and every gap
fixed gets a regression test.

- **Rung 0:** `debian:stable /bin/uname -m` → `x86_64` (Part 1 exit gate).
- **Rung 1:** multi-step `/bin/sh` pipeline on a glibc image (`ls -la / | wc -l`).
- **Rung 2:** `python3 --version` + a small script doing file I/O and stdout.
- **Rung 3:** `python3 -m http.server` — sockets/accept loop; curl it from the host.
- **Rung 4:** `apt-get install <pkg>` on debian/ubuntu — network, fork/exec of
  maintainer scripts, dpkg.

Per-rung loop: run under `CARRICK_TRACE_TRAPS=1` / `carrick trace`
(`scripts/dtrace/rosetta-open.d`, `scripts/dtrace/rosetta-fault.d`), isolate the gap
(ENOSYS / EFAULT / translator fault) with systematic-debugging, fix, add a test.
Gaps that materially expand scope are surfaced, not silently absorbed.

## Part 3 — Make it real (tests + conformance)

Today almost nothing automated covers the Rosetta execution path (a few redirect /
handshake / platform-parse unit tests + a shell demo). Add:

- **Unit tests** for each re-ported piece: `prctl` `PR_GET/SET_MEM_MODEL` (70 returns 0
  then 1; 71 arg2=1 → `SetMemoryModel{tso:true}`; unknown arg2 → `EINVAL`),
  `uname`→x86_64 selection (`carrick_x86_64` chosen iff loaded exe is the Rosetta
  interpreter), pointer-tag strip, ioctl handshake (truncation to the size field,
  `0x80456122`, Rosetta-absent branch), `SetMemoryModel` routing, high-VA alias map +
  `no_access` clear.
- **An amd64 conformance lane.** Parameterize `crates/carrick-cli/tests/conformance.rs`
  (today hardcoded `const PLATFORM = "linux/arm64"`) to add a `linux/amd64` lane that
  diffs carrick-via-Rosetta against `docker run --platform linux/amd64` on a glibc
  oracle (e.g. `ubuntu:24.04`): `uname -m`, `dpkg --print-architecture`, and a subset of
  the existing `/bin/sh` cases. **Self-skip** when Rosetta, Docker, or the amd64 image
  is unavailable (so CI on non-Rosetta hosts stays green). Add the missing amd64
  fixture/probe build path (`scripts/build-probes.sh` / `build-linux-fixtures.sh` build
  `aarch64-musl` only today).
- Fold `scripts/rosetta-demo.sh`'s assertions (including the Alpine exit-139
  known-limitation check) into the lane; keep the script as a convenience wrapper.

## Landing & docs

- Branch `feat/rosetta-glibc-amd64` off current `main`; commits reference original SHAs
  for provenance; pushable/PR-able to `origin` (`../carrick`).
- Rewrite `main`'s `docs/rosetta.md`: flip "TTBR1/upper-half is the next architectural
  step" → "done," document the glibc-dynamic end-to-end path and the static-PIE-musl
  limitation, and drop the stale pre-implementation "Open Questions" (Q1–Q4 are
  answered by the merged base).

## Verification environment (confirmed present)

Apple Silicon, **macOS 26.6** (≥ `macos-15`, so the `ACTLR_EL1.EnTSO` applevisor gate is
satisfied); **Rosetta 2 for Linux installed** (`/Library/Apple/usr/libexec/oah/
RosettaLinux/rosetta`, `/var/db/oah`); **Docker 29.5.2** (arm64) as the
`--platform linux/amd64` oracle; `just`/cargo/rustc 1.95. Runs require a **codesigned**
build (`just build`) and `CARRICK_ACCEPT_ROSETTA_TERMS=1`.

## Risks

1. **TTBR1 reconciliation against the rewritten `carrick-hvf` is the hard part** —
   the load-bearing MMU change re-applied into moved+rewritten code; expect iteration
   and careful verification that the native arm64 path is unaffected.
2. **`apt`/`http.server` may surface a long tail of amd64-specific gaps under Rosetta**
   (signal/fork/exec/socket-heavy). Scope could grow; gaps are surfaced as hit.
3. **Shared TTBR0/TTBR1 root** relies on lower/upper-half projections staying in
   disjoint L0 slots — an invariant maintained by layout, not enforced in code. Worth a
   debug assertion during re-port.
4. **Static-PIE musl stays out of scope** (Apple translator limitation).

## References

- `docs/rosetta.md` @ `origin/feat/rosetta-ttbr1` — authoritative status doc for the
  unmerged layer (working glibc path, decoded Alpine fault).
- `docs/rosetta.md` @ `main` — the base-era doc that still calls TTBR1 the next step.
- Commit range `origin/feat/rosetta-amd64..origin/feat/rosetta-ttbr1` (8 commits).
- `scripts/rosetta-demo.sh`, `scripts/dtrace/rosetta-open.d`, `scripts/dtrace/rosetta-fault.d`
  @ `origin/feat/rosetta-ttbr1`.
- `docker/for-mac#6773`, `crystal-lang/crystal#6934` — the static-PIE-musl Rosetta limit.
