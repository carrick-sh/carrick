# AGENTS.md

Operating manual for AI coding agents (and humans) working in **Carrick**. This
file is the index and the rulebook; depth lives in [`docs/`](docs/),
[`.agents/skills/`](.agents/skills/), and the [`justfile`](justfile). Read this
first, then follow the pointers.

> These rules were learned the hard way — each one is here because skipping it
> cost hours. They are not style preferences; they are load-bearing.

---

## What Carrick is

Carrick runs **unmodified Linux binaries as host-native processes**, with a Rust
syscall translation layer instead of a guest Linux kernel. There is no guest
kernel, no second scheduler, no separate hypervisor RAM pool, and the runtime is
BKL-free (per-subsystem locks, not a global lock).

**Two execution backends, and the distinction is load-bearing — know which one
you are testing:**

- **VMM** (`--exec-backend vmm`): a hardware-virtualized vCPU per guest thread.
  The macOS / Apple Silicon `Hypervisor.framework` (HVF) path running AArch64
  Linux guests is the **mature reference** lane — every `svc #0` traps to the
  host and carrick re-expresses Linux syscalls as Darwin primitives. The
  published conformance results (and `scripts/conformance/baseline.jsonl`) are
  this lane's.
- **NATIVE / DSR** (`--exec-backend native`): **no hypervisor at all** — guest
  code runs as host-native process state with a JIT for same-ISA translation.
  **This is the shipped DEFAULT** (`ExecBackendRequest::Native`,
  `crates/carrick-spec/src/lib.rs`), and it is the direction of travel (native
  is intended to replace VMM as the primary stable backend). Its conformance
  overlay (`baseline.native-dsr.jsonl`) is essentially empty, so its standing is
  materially less proven than the VMM numbers suggest — measure, do not assume.

Because the default and the well-measured lane are NOT the same, a gate that
does not name its backend is telling you about the other one.

The portability work splits that model across host/VMM and guest-ISA axes:
macOS/HVF, Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM, and active x86_64 guest
bring-up through the shared `carrick-x86` engine. Treat the macOS/HVF path as
the release-quality reference lane; treat non-macOS and x86_64 paths as active
bring-up unless the exact target-host gate proves otherwise.

**Status — experimental, not production-ready.** Be honest in code, comments,
docs, and commit messages: syscall coverage is partial (225 emulated, 112
deferred on the aarch64 table — count them with
`grep -c 'SupportLevel::BringUp' crates/carrick-abi/src/syscall.rs` — several
only partial; see [`docs/syscalls-emulation-map.md`](docs/syscalls-emulation-map.md)),
guest behaviour is incomplete, and there has been **no adversarial security
review**. A guest is not a hardened trust boundary — do not run untrusted code
under it, and never describe it as "complete" or "production-ready."

---

## ⚠️ Rule 0 — codesign before you run the VMM path

**Scope:** this rule is about the **VMM/HVF** backend. A guest on that path only
runs from a **codesigned** binary: a bare `cargo build` strips the
`com.apple.security.hypervisor` entitlement, so `carrick run --exec-backend vmm`
dies with **`HV_DENIED` (`0xfae94007`)**.

**The NATIVE backend (the shipped default) needs NO entitlement and no
hypervisor** — it uses `MAP_JIT` under ad-hoc signing with no hardened runtime
(`crates/carrick-native-darwin/src/jit.rs`), which is why native guest tests run
from an ordinary `cargo test` binary. If you are on the native path and hit
`HV_DENIED`, you are not on the native path — check `--exec-backend`.

- **Build/run via `just build` / `just run`** — both go through
  [`scripts/build-signed.sh`](scripts/build-signed.sh), which re-applies the
  entitlement (`scripts/entitlements.plist`) after linking. Use plain
  `cargo build` (`just check`) only to compile-check, never to run a guest.
- **After changing `carrick-runtime`, rebuild `-p carrick-cli` and re-sign.**
  Building the runtime lib alone does **not** relink `target/release/carrick`, so
  you'll test a stale binary. Confirm the new code is in the binary:
  `strings target/release/carrick | grep <your-marker>`.
- **Never swap in a faster linker (`lld`).** It strips the `__DATA,__dof_carrick`
  section → USDT probes register empty → `carrick trace` silently fires zero
  events. Keep Apple `ld64`. Verify: `otool -l target/release/carrick | grep dof`.
- Distribution is a HEAD-only Homebrew tap
  (`brew tap carrick-sh/carrick && brew install --HEAD carrick`); the formula
  re-signs the entitlement in `def install`, same reason.

---

## Commands

The [`justfile`](justfile) is the source of truth. Recipes that **codesign** are
marked 🔏 (use these to run/conformance-test a guest); the rest are
compile/lint/test only.

| Command | Purpose |
|---|---|
| `just build [ARGS]` 🔏 | Build + codesign the release binary (required to run a guest). |
| `just run [ARGS]` 🔏 | `just build` then run `target/release/carrick ARGS`. |
| `just check [ARGS]` | Fast **unsigned** `cargo build` — compile-check only, cannot run a guest. |
| `just test` | Host lib tests (no HVF/Docker). **Use the recipe, never a bare `cargo test --workspace --lib`** — carrick-runtime's tests fork from the harness and deadlock when run in parallel, so the recipe runs every OTHER crate in parallel and then carrick-runtime alone under `RUST_TEST_THREADS=1`. |
| `just test-integration` | Host integration suites (`carrick-runtime`/`engine`/`image`; no HVF). |
| `just clippy` | `cargo clippy --workspace --all-targets -- -D warnings` (no-panic gate). |
| `just fmt` / `just fmt-check` | Apply / check formatting. |
| `just doc` | `RUSTDOCFLAGS="-D warnings" cargo doc` gate. |
| `just lint-domains` | Typed-domain semgrep gate ([`.semgrep/typed-domains.yml`](.semgrep/typed-domains.yml)) — blocks shipped bug shapes; see Engineering standards. |
| **`just ci`** | **Full local gate: `fmt-check → clippy → lint-domains → deny → check-matrix → check → doc → test → test-integration`. Run this before every push.** |
| `just conformance-quick` 🔏 | Fast smoke regression vs the Docker oracle. |
| `just conformance [TIER]` 🔏 | Language/LTP conformance vs Docker (default tier `full`). |
| `just conformance-probes` 🔏 | Line-exact ABI probe gate vs Docker. |
| `just matrix` | Re-render [`docs/support-matrix.md`](docs/support-matrix.md) from a run's results. |
| `just check-matrix` | Drift gate (in `just ci`): assert `docs/support-matrix.md` equals a fresh render of the checked-in `baseline.jsonl` (deterministic, no run). |
| `just kvm-smoke` / `just kvm-smoke-lima` | KVM backend smoke (real `/dev/kvm`, via lima from macOS). |
| `just install-hooks` | Install the git hooks (do this once per clone). |

**Toolchain:** the pin, edition, workspace members and the `deny`ed lints live in
[`rust-toolchain.toml`](rust-toolchain.toml) and [`Cargo.toml`](Cargo.toml) —
read those, their comments explain the why. The one thing not written there: CI
pins the toolchain via `@stable` (moving), so a freshly released stable can flag
lints your pinned local toolchain doesn't — keep local in sync with
`rustup update stable`.

---

## Repository map

**[`crates/README.md`](crates/README.md) is the crate map** — every crate's role,
the product path `cli → engine → {image, runtime} → spec`, and the per-platform
feature-closure rules. Read it rather than a summary here; it does not go stale.
The HAL/platform split ([`docs/hal.md`](docs/hal.md)) separates platform-neutral
contracts from per-VMM and per-host implementations so KVM/bhyve/NVMM can share
the runtime without pulling in HVF/applevisor.

Two conventions the code alone would teach wrong:

- **Use the `carrick-vmm-*` names for VMM crates** (`carrick-vmm-hvf`, not the
  historical `carrick-hvf`).
- **The native (DSR) drivers have exactly ONE wiring point.** Two driver FILES
  serve THREE lanes: `carrick-runtime/src/native_darwin.rs` (aarch64) and
  `src/native_freebsd.rs` — which despite its name is the shared x86_64 run
  loop for BOTH FreeBSD and NetBSD (`cfg(any(freebsd, netbsd), x86_64)`; a
  rename to a lane-neutral name is deferred for git-blame continuity). They
  route exclusively through `carrick-runtime/src/native/mod.rs`
  (`type HostNativeLane` resolves to `DarwinAarch64Lane`, `FreebsdX8664Lane`,
  or `NetbsdX8664Lane`), plus its `native/fork_child.rs` shared post-fork
  dispatcher reset. Don't add a second.
  Seam design:
  [`docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md`](docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
  Phase 1 plan:
  [`docs/superpowers/plans/2026-07-23-native-lane-seam-phase1.md`](docs/superpowers/plans/2026-07-23-native-lane-seam-phase1.md).
  The once-planned Phase-2 merge of the two drivers' thread loops was
  **evaluated and SKIPPED** — a precision scout found the loops share only
  ~10% and that the danger zones (fault lowering, x86 XSAVE vs aarch64 FP
  xstate) are not callback-able without semantic entanglement. What landed
  instead is engine-level symmetry: the x86 translate/cache engine was
  extracted to `carrick-dsr-x86::translator`, mirroring
  `carrick-dsr-aarch64::translator`. Do not re-plan the loop merge without
  reading that finding first.

### Where key subsystems live
- **Trap loop / syscall dispatch** — mature macOS trap loop in `crates/carrick-vmm-hvf/src/trap.rs`; x86 loop in `crates/carrick-x86/src/engine.rs` with backend adapters; dispatch in `crates/carrick-runtime/src/dispatch/mod.rs` (`SyscallDispatcher`, per-subsystem locks); syscall metadata in `crates/carrick-abi/src/syscall.rs` and guest-arch tables under `carrick-hal`.
- **VFS / rootfs** — `crates/carrick-runtime/src/dispatch/fs.rs`, `crates/carrick-runtime/src/vfs/` (in-memory OCI layer merge; `--fs host` cap-std backend — see [`docs/fs-host-capstd-amplification.md`](docs/fs-host-capstd-amplification.md)).
- **Memory / paging** — `crates/carrick-mem/src/memory.rs` (stage-1 identity map, EL0 trampoline, FEAT_PAN3 workaround); mmap arena `crates/carrick-runtime/src/dispatch/mem.rs`.
- **Signals** — `crates/carrick-runtime/src/dispatch/signal.rs` (Linux↔macOS signum translation, sigreturn trampoline).
- **Threads / futex** — `carrick-thread`; fork barrier `crates/carrick-vmm-hvf/src/fork_quiesce.rs` (one pthread = one vCPU).
- **epoll / sockets** — event backends in `carrick-host-bsd` (kqueue) and `carrick-host-linux` (epoll); sockets `crates/carrick-runtime/src/dispatch/net.rs` (synthetic `AF_NETLINK`, AF_UNIX path-hash registry).
- **ptrace / pty** — `docs/ptrace-darwin-design.md` (Phase 1 only); pty `crates/carrick-runtime/src/pty_relay.rs` + `interactive_supervisor.rs`, `vfs/devpts.rs`.
- **x86 / Rosetta** — `linux/amd64` images via Apple's in-guest Linux Rosetta (`docs/rosetta.md`).
- **Event ring (debug)** — always-on lock-free fork/socket/epoll ring `crates/carrick-runtime/src/event_ring.rs`, read via `scripts/carrick_lldb.py`.

---

## Conformance & the Docker oracle

Carrick's correctness oracle is **native arm64 Docker Linux**. The method is
differential: run the same thing under carrick and under Docker, diff the result.
If it fails in Docker too, it's not carrick's bug.

- **Never run carrick and the Docker oracle concurrently.** Both are heavy VMs
  (HVF guest vs the LinuxKit VM) and starve each other → slow and *wrong*
  verdicts. The gate is **two-phase**: run all carrick cases, then all Docker
  cases. `carrick‖carrick` and `docker‖docker` are fine; `carrick‖docker` is not.
- **Stamp `CARRICK_RUN_ID`; reap with [`scripts/sudo/kill.sh`](scripts/sudo/kill.sh) `<run-id>`.**
  Never `pkill -f carrick` — it kills concurrent lanes and other worktrees.
- **Oracle is native arm64 only.** Never use a Rosetta-translated
  `--platform linux/amd64` container as an x86_64 oracle; if you need an x86
  oracle, ask the user for a native box.
- **Cross-platform lanes test the other VMM backends on real hardware.** The
  harness (`carrick-conformance`) is platform-neutral — it shells out to the
  built `carrick` binary — so the same gate runs on Linux/FreeBSD/NetBSD via
  `--lane kvm-local` (Linux `/dev/kvm`), `--lane bhyve-local` (FreeBSD),
  `--lane nvmm-local` (NetBSD). Those `*-local` lanes inject
  `--platform linux/amd64` (x86_64 guests) and set `CARRICK_INSECURE_REGISTRIES`.
  Off macOS the binary needs `cargo build -p carrick-cli --no-default-features
  --features platform-<linux|freebsd|netbsd>` (the default `platform-macos`
  pulls in `carrick-vmm-hvf`/`applevisor`, which don't compile off macOS — E0433;
  `scripts/build-signed.sh` is macOS-only). x86-lane excuses go in the
  `baseline.kvm.jsonl` overlay, not the main baseline. A box without a local
  registry can still source images over an SSH tunnel
  (`ssh -R 5005:<registry-host>:5005 <box>`) since carrick treats `localhost:5005`
  as insecure. When **multiple agents share one working tree**, sync a box with
  ONLY the files you yourself changed (and `md5`-verify a dependency before
  trusting box state) — a blanket `rsync crates/` ships another agent's mid-edit
  breakage into your box build.
- **The Docker oracle is cached** (`scripts/conformance/oracle-cache.jsonl`) so
  routine gates run carrick-only. Single-run gating is non-deterministic
  (Go-under-HVF races); treat flaky flips as flakiness (retry / `known_gaps`),
  not regressions.
- **Linux syscall shape comes from `bpftrace` INSIDE the Docker oracle — never
  from guest `strace`.** `strace` perturbs test behaviour and is not accepted as
  Docker-oracle syscall evidence. The container ships `bpftrace`; run it in a
  Docker-only phase, never alongside carrick. Full recipe (privileges, the
  tracefs mount, tool validation) in
  [`.agents/skills/ltp-conformance`](.agents/skills/ltp-conformance).
- **The cache key is the suite *declaration*, not the image digest.** It is a
  stable JSON of `OracleKey` (image, cmd, env, `docker_platform`, verdict…), so
  the committed cache stays valid across machines that may not have the images.
  The trap: adding/renaming a determinant field (e.g. `docker_platform`)
  invalidates **every** committed key at once → the gate logs `0 cached oracle(s)`
  and runs a **full fresh Docker pass** (slow), then rewrites `oracle-cache.jsonl`
  with the new schema. That post-gate rewrite is a **legitimate re-bless — commit
  it** (it makes the next gate fast again) *when the run was on the canonical box
  with correct images*. Only `git checkout` it away when the rewrite is spurious
  (a box missing/with wrong images). Force a clean re-bless with `--refresh-oracle`.
- **TDD, red-first.** When adding a conformance probe or fixing a syscall, prove
  the probe is **red against the broken binary first**
  (`git checkout <pre-fix> -- <file>`, rebuild signed, confirm DIFF), then restore
  the fix and confirm MATCH. A probe that passes immediately proves nothing.
- **Attribute a gate REGRESSION/CRASH before you fix it — don't assume it's your
  change.** Reduce to a fast reproducer, then ask in order: does Docker fail it
  too, does the pre-change binary fail it, and what did the blessed baseline say?
  A load-probabilistic verdict will make a one-run-per-point bisect converge on
  the WRONG commit — sample each point ≥2× and suspect the PROBE before the
  runtime. The full procedure and two worked examples (`cpython-socket`,
  `expectcontinue`) are in
  [`.agents/skills/ltp-conformance`](.agents/skills/ltp-conformance).
- **Probe-gate mechanics that silently lie:** the gate's logs contain binary
  bytes — grep them with `-a` or your matches vanish without error. And run the
  gate (`cargo test -p carrick-cli --test conformance conformance_probes`) from
  the **repo root**: from any other cwd it finds no probe binaries, SKIPs every
  lane, and reports `ok` in 0.04s — a green that gated nothing.
- **LTP parity is NOT workload coverage.** LTP cases are small enough to miss
  whole blocker classes: no LTP case pushes `brk` past 4 MiB, so the bhyve
  heap-backing bug that crashed **100% of cpython** hid behind a healthy ~70%
  LTP score for weeks. Rank fix work by running the real ecosystems
  (go/cpython/node) on a lane — `--ecosystem` filters — not by LTP counts alone.
- Skills: [`.agents/skills/ltp-conformance`](.agents/skills/ltp-conformance) (LTP
  triage), [`.agents/skills/carrick-trace`](.agents/skills/carrick-trace). Local
  oracle registries and suite wiring: [`docs/conformance-testing.md`](docs/conformance-testing.md).

---

## Debugging

Use **real debuggers, not `eprintln!`** — and never ship debug spam. Full guide:
[`docs/diagnostics-and-debugging.md`](docs/diagnostics-and-debugging.md).

- **`carrick trace` is THE tracer** (in-process libdtrace/USDT). Extend it; don't
  hand-roll one-off `.d` scripts. It **auto-sudos** (don't prefix `sudo`
  yourself), predicate on `pid == target || progenyof(target)` to follow forks,
  and kill leftover `carrick run` procs first. Default guest `ubuntu:24.04` (frame
  pointers → stack walking works). Skill:
  [`.agents/skills/carrick-trace`](.agents/skills/carrick-trace).
- **`.d` scripts are DURABLE ARTIFACTS, not scratch.** Everything under
  [`scripts/dtrace/`](scripts/dtrace/) is kept, named for the question it
  answers, and carries a header stating (a) what it measures, (b) the provider
  ABI facts qualified live on the host it was written for, and (c) whether it
  perturbs. Never delete one because an investigation ended — the next
  investigation starts from it. When you learn a probe fact the hard way, write
  it into the script header so nobody pays for it twice.
- **`carrick trace` should PREVENT the traps below, not just expose probes.**
  Every trap here has cost real hours; each one that can be mechanically
  detected belongs in the harness, failing closed with a named error rather than
  producing a plausible-looking empty result:
  - **A listed probe is not a firing probe, and FBT is blind to LOCAL symbols.**
    `dtrace -l` lists `fbt::vm_fault:entry` on arm64 macOS but it never fires.
    The reason is not that the fault avoids `vm_fault` — it is that FBT
    instruments the *exported* `_vm_fault`, which is merely an alias of
    `_vm_fault_external` (`0xfffffe000742b0b8`), while the trap path
    (`fleh_synchronous → sleh_synchronous → handle_user_abort`) calls the
    **local** `_vm_fault_internal` (`0xfffffe00074210f8`, nm type `s`) — and
    FBT exposes zero local symbols on this build. When a probe you are sure
    about stays silent, **check the KDK dSYM for a local twin**
    (`nm -a …kernel.release.t8132.dSYM/…` and compare addresses) before
    concluding the code path does not run. Trap-context functions
    (`handle_user_abort`, `arm_fast_fault`) are separately FBT-blacklisted, so
    there is still no entry/return pair to time — those costs must be
    **sampled, not bracketed**.
  - **Kernel stack frames can be SYMBOLIZER ALIASES.** Several names resolve to
    one address, and dtrace may print the misleading one: `IORWLockUnlock` IS
    `lck_rw_done` (`0xfffffe0007377f88`), `IORWLockRead` IS
    `lck_rw_lock_shared`, `IOLockLock` IS `lck_mtx_lock`. An "IOKit" frame in a
    VM profile is usually plain rw-lock traffic. Confirm a suspicious frame by
    address against the dSYM before building a story on its name.
  - **Zero events means "the probe did not fire," never "it did not happen."**
    A capture that yields nothing must be an error, not an empty summary.
  - **`execname` scoping silently tracks nothing** the moment two arms are built
    under different binary names. Cross-binary screens must key on carrick's own
    `carrick*:::dsr-cache-*` lifecycle probes under `dtrace -Z`.
  - **Provider ABIs differ per host/build and must be qualified live**, not
    assumed (`sched:::preempt` does not exist on macOS; `vminfo:::as_fault`
    arg2 IS the exact 16 KiB host-page base).
  - **Kernel providers only against a live native guest** — never `dtrace -p`,
    `-c`, pid-provider, or USDT fasttrap on a continuing native process.
  - **Declare perturbation.** A probe on a 2M-events/run path can double `sys`
    time; a script that perturbs must say so, and only same-instrument ratios
    are then citable.
- **When tracing perturbs a Heisenbug away, read the always-on event ring via
  `carrick-lldb`** — works live or from a core, with nothing pre-armed. Attach the
  **guest** process, not the orchestrator parent (the parent's ring is empty).
  Skill: [`.agents/skills/carrick-lldb`](.agents/skills/carrick-lldb).
- **For a wedged/deadlocked process, take a real CORE and `bt all`**
  (`sudo lldb -p <pid> -o "process save-core …" -o detach`). `sample`/`SIGQUIT`
  have mislabeled fork-quiesce deadlocks as lost-wakeups — don't trust them.
- **Verify diagnoses empirically.** A "race / coherence / Heisenbug" label is the
  easiest place to be wrong. Instrument the exact failure point and read the real
  values before changing code; treat memory notes and prior diagnoses as
  hypotheses, not facts. Also verify *how you read the result* — empty output may
  mean "ran but unreadable," not "didn't happen."

### Debugging the FreeBSD/amd64 native (DSR) lane

The x86_64 native lane (`carrick-runtime/src/native_freebsd.rs`, driver
`runtime::run_elf_native_dispatch`) runs guest code from a JIT cache with the
`carrick-dsr-x86` gateway. `carrick trace` targets the container/VMM run, not
this bare in-process runner. **Never use `dtrace -p`, pid-provider probes, or
USDT fasttrap probes on a continuing native process** — a detach leaked
`SIGTRAP` and killed a live Kaniko build; the supported profiler
(`sudo scripts/native-x86-profile.py PID`) uses kernel providers only. **Never
hardcode the context offset** (XSAVE expansion moved it from 720 to 33024), and
**the native-x86 gateway is zero-copy by contract** — 16,384/16,576-byte
`memcpy` samples that scale with gateway entries are a performance-correctness
failure. The launch-time `native_run` driver, the USDT census recipe, the
gcore-and-disassemble-the-JIT procedure, and the JIT-unwind TODO are in
[`.agents/skills/carrick-native-debug`](.agents/skills/carrick-native-debug).

---

## Engineering standards

**The two gates. Nothing else matters if these fail: correctness, and
"zero"-overhead.** Carrick's whole premise is running Linux binaries at
host-native cost. A correct-but-slow runtime and a fast-but-wrong one are both
dead ends, so every change is judged against those two first and against
elegance, generality or effort saved second. Overhead is not a "later"
concern — it is half the product.

- **The overhead bar is WITHIN 2x of native-arm64 Docker** on the same workload.
  That is the number to rank against. As of 2026-08-01 the native lane is
  **~14.5x** on the cold go-build, so reaching the bar means removing roughly
  93% of all non-guest CPU — every overhead bucket, not one of them. Rank work
  by whether it can plausibly be a multiple, and be honest that a 3-15%
  improvement does not move a 14.5x ratio. Evidence:
  [`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md`](docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md).
- **The overhead workstream is one thing: "utilize Darwin in the most efficient
  way to emulate Linux."** Carrick's own host userspace (36.9% of CPU) and the
  kernel work it induces — page faults (25.7%) plus syscall bodies (9.9%) — are
  not separate problems. They are the cost of LOWERING one Linux operation onto
  Darwin primitives, measured on the two sides of the syscall boundary, and
  together they are **72.5% of the budget**. Rank by the **amplification factor
  of a single guest operation**, which is concrete and directly attackable
  where a CPU percentage is not:
  - guest `open` → **19.68 host opens** at HEAD (cap-std path re-walks), even
    after `564dd281` cut it 41%;
  - guest `mmap(MAP_PRIVATE, fd)` → a `pread` of the FULL mapping length into
    fresh anon (`dispatch/mem.rs:2517`), instead of a host file-backed mmap;
  - guest `execve` → 4 full ELF materializations + 3 SHA-256 passes + a host
    self-re-exec, while the file-backed `map_prepared_for_plan`
    (`mapped_memory.rs:1018`) sits marked `dead_code`;
  - guest `MAP_FIXED|MAP_ANONYMOUS` → an unconditional full remap.
  Drive each toward 1. **Do NOT assume carrick's own copies cause the fault
  term** — the committed census refutes it: JIT first-touch is 2.08% of zfod and
  inserted code 1.48%, so faults are dominated by the GUEST's own anonymous
  memory. The lever there is making each guest page cheaper on Darwin, not
  making carrick copy less.
- **Use Go's runtime as a DUAL-PORT ORACLE for "what should this lower to on
  Darwin?"** Go implements the same allocator abstractions (`sysAlloc`,
  `sysReserve`, `sysMap`, `sysUnused`, `sysUsed`, `sysFault`, `sysFree`)
  separately for `linux/arm64` and `darwin/arm64`, so diffing
  `$GOROOT/src/runtime/mem_linux.go` against `mem_darwin.go` shows exactly how
  one intent is expressed idiomatically on each OS. It is BSD-licensed — reading
  it is explicitly fine, unlike the Linux kernel side. Other subsystems
  (`os_darwin.go`, `sys_darwin.go`, signal and thread handling) serve the same
  purpose.
  - Worked example: **Go's Darwin port uses NO `mprotect` at all** for heap
    management. Its whole vocabulary is `mmap(MAP_ANON|MAP_PRIVATE)` to
    allocate, `mmap(PROT_NONE, …|MAP_FIXED)` to protect/fault,
    `mmap(PROT_READ|WRITE, …|MAP_FIXED)` to commit, and the
    **`MADV_FREE_REUSABLE` / `MADV_FREE_REUSE` pair** to decommit/recommit
    (leaving the VM entry intact). `mem_linux.go` DOES use `mprotect`. Same
    allocator, same intent, different primitive — because on Darwin `mprotect`
    is the expensive way.
  - The lesson generalizes: **translate the guest's INTENT, not its mechanism.**
    A guest `mprotect(PROT_NONE)` on heap means "decommit"; faithfully
    re-issuing a host `mprotect` reproduces a Linux idiom on the OS where it is
    the wrong one. Ask what a native Darwin program wanting that semantic
    actually calls, and lower to that.
- **Correctness is not tradeable for overhead.** A guest-visible ABI guarantee
  (e.g. anonymous `mmap` returning zeroed pages) is immovable — do not weaken
  one behind a "provably safe" fast path. Find a lever that removes the work
  instead of removing the guarantee. Note this usually costs nothing: mapping an
  image file-backed, or letting Darwin's zero-fill deliver a pre-zeroed page
  instead of memsetting it yourself, removes work AND keeps the guarantee.
- **A perf claim is a HYPOTHESIS until it comes from a controlled,
  single-variable experiment.** One knob at a time, everything else held —
  including the core class. On Apple Silicon `hw.logicalcpu` is NOT homogeneous
  (this host is 4 Performance + 6 Efficiency), so a concurrency sweep silently
  changes which cores run the work and is never a clean variable. Anything less
  than a controlled experiment is written as "suggests", never "confirmed".

**No backward compatibility. We are our own ecosystem.** There is no external
consumer to keep working, so do NOT carry a legacy path, a V2 beside a V3, a
compatibility shim, or a deprecated spelling. Replace it and delete the old one.
The cost of a second path is not the code — it is that every future measurement,
test and reader now has two answers to reconcile.

**Rust first, and extend OURSELVES rather than growing a tool zoo.** The first
language you reach for is Rust, and the first home for a new capability is our
own binary — a `carrick trace` profile or a `carrick debug` subcommand — not a
new standalone script.

- **D scripts** are for what only D can do, and they belong to a Rust profile
  rather than standing alone: `carrick trace` hashes a profile's D program into
  its output header (`program_sha256`), so the script becomes an authenticated
  input with a Rust parser and validator around it. A new `.d` should arrive as
  a new `TraceProfileKind`, not as a file someone runs by hand.
- **Python** is for driving lldb, where it is the only in-process option.
- Everything else — capture orchestration, parsing, validation, statistics,
  report generation — is Rust in our own crates, where the type system, `just
  ci`, and `-D warnings` apply. Ad-hoc shell/Python harnesses are untyped,
  untested, ungated, and drift from the runtime they measure.
- Rust owns the truth; the D script consumes it. `carrick debug
  native-x86-layout` exists precisely so offsets are read from the running
  binary instead of hardcoded into a `.d` — follow that pattern.

**Look for what already exists before writing anything new.** This tree is large
and has usually already solved the adjacent problem. Grep for the mechanism, the
probe, the helper, the harness — and read it — before adding a parallel one. A
second implementation is worse than a slightly-wrong first one, because now both
drift. (Worked example: a fault-address census, its parser, and its test already
existed as `scripts/dtrace/native-fault-attribution.d` +
`scripts/perf/native_fault_directional.py` while a campaign doc was still
recording the fault term as "blocked on instrumentation.")

**Opt-OUT, not opt-in — a default-off mechanism is not shipped, it is
abandoned.** This project has repeatedly built a mechanism, gated it behind
`FEATURE=1`, and then left it dead for months: the whole container-lifetime
shared-translation lane, the H004 direct-binding sidecar, and the artifact spike
are all in the tree, compiled, tested and unreachable. That pattern hides
regressions (nobody runs the arm), rots the code (it drifts from the default
path), and lets a "landed" change never actually land.

- New work defaults **ON**, with an exact `=0` escape hatch for bisection.
- If it cannot be defaulted on, it is not finished — say so plainly rather than
  merging it dark.
- When a mechanism is MEASURED WORSE, **delete it**; do not park it behind a
  flag. `git` is the version control — the code is recoverable, and a commit
  message pointing at the measurement is worth more than dead code carrying an
  implication that it might still be a good idea.
- The same applies to tests: a test that no gate executes is not a test. Check
  that a new suite actually runs (`carrick-cli` has no lib target, so its
  in-file `mod tests` and integration suites are compiled by clippy and never
  run by `just test`/`just test-integration`).

- **NEVER read Linux kernel or other GPL source when implementing carrick.**
  Clean-room only: derive ABIs from man-pages/specs and the differential Docker
  oracle (`bpftrace`/observe behaviour, diff verdicts). This is
  non-negotiable.
  (Reading LTP *test* source — the oracle itself — is a separate, grayer matter.)
- **Typed domain values are the baseline — bare `u64`/`i32` never crosses a
  semantic boundary.** Three shipped bugs (the `!wait_set` polarity hang, the
  `alarm`↔`epoll_create` private-number collision, the poll int-vs-timespec
  timeout) all reduce to "two domains shared one integer type". The rules,
  ranked audit, and staged plan live in
  [`docs/typed-interfaces-audit.md`](docs/typed-interfaces-audit.md):
  - Use the existing types; don't re-raw them: `Fd`/`HostFd` (guest vs host
    descriptors), `NsPid`/`HostPid` (translate, never wrap the wrong domain),
    `Signal`, `GuestPtr`/`GuestLen`, `SigSet`/`SigBlockMask`/`WaitSigMask`
    (set vs park-mask polarity), `CanonicalNr`/`NativeNr` (syscall numbering),
    `GuestVa`/`Gpa`/`HostVa` (address spaces), `LinuxErrno`
    (`guest_retval()` is THE negation point), and the `bitflags` types.
  - New number/flag tables derive from an ordinal enum or `bitflags!` — never
    hand-numbered constants (add a compile-time uniqueness assert when a table
    can't be an enum).
  - Where polarity or direction matters, the type has NO general `from_raw`:
    construction goes through a NAMED semantic constructor
    (`SigBlockMask::for_signal_wait`, `WaitSigMask::Additive/Replace`). Raw
    escapes only at libc/wire/atomic boundaries via explicit `.raw()`/`.get()`.
  - Enforcement is mechanical, not aspirational: workspace-`deny`ed
    `unreachable_patterns` + `bindings_with_variant_name` (the unimported-const
    match-arm catch-all is a build failure), and **`just lint-domains`** — the
    semgrep gate ([`.semgrep/typed-domains.yml`](.semgrep/typed-domains.yml))
    that blocks the shipped bug shapes (raw wait-set complements, bit=`signum`
    masks, host pids in `NsPid`, hand-numbered private numbers, function-local
    `LINUX_*` consts, inline errno negation). It runs inside `just ci`.
  - Mechanical migrations go through
    [`scripts/migrate/rewrite.py`](scripts/migrate/rewrite.py) (count-asserted,
    all-or-nothing rewrite specs) so a repeated-shape pass is a reviewable
    artifact, not a pile of hand edits.
- **No pragmatic shortcuts — fix the root cause.** If a backend has a bug, fix the
  backend; don't gate it with a shell hack, swap a real implementation for a
  cheaper approximation, or paper over it. If you catch yourself reaching for a
  workaround, stop and do it properly.
- **Definition of Done = live-verified end-to-end, not "it compiles."** Don't
  report a goal complete until you have a clean build, passing tests, **and** an
  actual runtime demo of the behaviour. If something compiles but fails at
  runtime, it isn't done.
- **Prefer Darwin-native kernel mechanisms** over hand-rolled userspace
  (`sendfile(2)`, `kqueue`/`EVFILT_*` for epoll, `__ulock` for futex, macOS ptys).
  Userspace reimplementations tend to deadlock the vCPU or mishandle
  EAGAIN/backpressure.
- **Fill Linux/macOS gaps with durable macOS-native state, not in-process maps.**
  carrick forks real host processes for `clone(2)`, so in-memory `HashMap`/global
  state is **not fork-coherent** and silently diverges. Use xattrs, fds, host
  kernel bookkeeping (e.g. guest file modes live in a `user.carrick.mode` xattr).
- **Use the `libc` crate, not ad-hoc `extern "C"` blocks** (`libc::fork`,
  `waitpid`, `pipe`, `ioctl`, …). Exception: `applevisor-sys` raw `hv_*` bindings.

---

## Commits, hooks & CI

- **Subject — Conventional Commits: `type(scope): subject`** (imperative,
  lowercase, no trailing period, ≤~72 chars). Types in use: `feat`, `fix`,
  `refactor`, `docs`, `test`, `diagnostics`. Real scopes: `bhyve`, `kvm`, `nvmm`,
  `runtime`, `conformance`, `hal`, `host`, `bsd`, `linux`, `abi`, `arch`,
  `portable`, `x86`. Scope is optional.
  - e.g. `feat(runtime): run x86_64 oci images on kvm`, `diagnostics(kvm): report registers on internal errors`.
- **Body — write one; a lone subject line is NOT our style.** Reserve one-line
  commits for the genuinely trivial (a typo, a version bump). Anything that
  changes behaviour gets a blank line then a wrapped (~72-col) body a reviewer
  can follow WITHOUT reading the diff. Cover, in order:
  - **Why** — the root cause / the wrong behaviour and the Linux (or host)
    semantics being matched. Name what broke and for whom — a workload, an LTP
    case, a probe — never just "fix bug".
  - **What** — the approach, plus any deliberate approximation or divergence from
    exact Linux behaviour (be candid — honest status framing applies to commit
    messages too, not just docs).
  - **Verified** — how you proved it: the probe name, unit test, LTP case, or
    Docker-oracle diff. "Definition of Done = live-verified end-to-end" — the
    body is where you show the receipts; a red-first probe is worth naming.
  - `-` bullets when a fix has distinct parts; prose for a single change. Write
    symbols/paths as backticked identifiers so the message greps.
- **Trailer — end agent commits with a `Co-Authored-By:`** crediting the agent
  (model or tool) that did the work, one line after a blank line, matching the
  surrounding history — e.g. `Co-Authored-By: Codex <codex@openai.com>`. When
  rewording another agent's commits, reword the message but PRESERVE the original
  author (reword, don't re-author).
- **Hooks** (install once with `just install-hooks`): pre-commit runs `fmt-check`,
  pre-push runs `clippy`. **Never `git commit --no-verify`** to skip the fmt hook —
  if `fmt-check` fails, run `just fmt` and fix it. (If `cargo fmt` touches
  unrelated files, that's toolchain skew — `git checkout` those, don't commit them.)
- **CI runs the gate sequentially** (`fmt → clippy → build → doc → test →
  integration`), so **a red early step masks every later failure**. After any
  fmt/clippy fix, run the full **`just ci`** locally before concluding it's green.
- **ABI constants live in `carrick-abi`.** Don't add column-0 `const LINUX_*` /
  `SYS_*` in the dispatch files. A new `LINUX_*` used as a match arm but not
  imported becomes a silent catch-all that shadows later arms — always check for
  `unreachable pattern` warnings.

---

## Where to look next

| Doc | Covers |
|---|---|
| [`README.md`](README.md) | Install, quick start, what's implemented today. |
| [`docs/architecture-overview.md`](docs/architecture-overview.md) | The deep dive: HVF trap boundary, stage-1/FEAT_PAN3 paging, BKL-free concurrency. |
| [`docs/syscalls-emulation-map.md`](docs/syscalls-emulation-map.md) | Per-syscall support map: fidelity + backing Darwin mechanism. |
| [`docs/diagnostics-and-debugging.md`](docs/diagnostics-and-debugging.md) | `carrick trace`, event ring + carrick-lldb, `carrick debug`, debug Cargo features. |
| [`docs/conformance-testing.md`](docs/conformance-testing.md) / [`conformance-coverage.md`](docs/conformance-coverage.md) | Running/interpreting suites; the probe→invariant gate map. |
| [`docs/support-matrix.md`](docs/support-matrix.md) | Auto-generated carrick-vs-Docker verdict table (run `just matrix` to refresh). |
| [`docs/hal.md`](docs/hal.md) | Multi-platform HAL plan (macOS/FreeBSD/Linux/NetBSD backends). |
| [`docs/syscall-shim-design.md`](docs/syscall-shim-design.md), [`namespaces-design.md`](docs/namespaces-design.md), [`ptrace-darwin-design.md`](docs/ptrace-darwin-design.md), [`rosetta.md`](docs/rosetta.md) | Subsystem designs. |
| [`.agents/skills/`](.agents/skills/) | `carrick-trace`, `carrick-lldb`, `ltp-conformance`, `bifrost-trace-linux-guest` — task playbooks. |
