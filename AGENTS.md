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

**Execution Architecture — HVPatch Unified Kernel:**

- **HVPATCH** (`--exec-backend hvpatch`, default): Carrick's execution model.
  It keeps Linux tasks, process identity, address spaces, waits, and signals in
  Carrick's kernel graph and multiplexes them inside one VM carrier; guest
  `fork`/`clone` do **not** create separate host processes.
- **Host Hypervisor Implementations**:
  Hardware-assisted virtualization is provided per host: macOS / Apple Silicon
  `Hypervisor.framework` (HVF) running AArch64 guests is the release-quality
  reference lane; Linux/KVM, FreeBSD/bhyve, and NetBSD/NVMM bring the Carrick
  kernel to additional host platforms, with x86_64 guest bring-up through the
  shared `carrick-x86` engine.
- **Binary Patching & Translation Primitives (Preserved for Optimization)**:
  `carrick-native-darwin`, `carrick-dsr`, `carrick-dsr-aarch64`, and
  `carrick-dsr-x86` provide JIT translation, Apple Silicon `MAP_JIT` W^X
  primitives, and Tier-D direct binary patching, preserved as building blocks
  for future OS-level performance optimizations.

The legacy 1:1 host-process-per-guest-process execution backends (legacy `vmm`
and `native`) have been retired in favor of the consolidated HVPatch kernel.

**Status — experimental, not production-ready.** Be honest in code, comments,
docs, and commit messages: syscall coverage is partial (242 emulated, 95
deferred on the aarch64 table — count them with
`grep -c 'SupportLevel::BringUp' crates/carrick-abi/src/syscall.rs` — several
only partial; see [`docs/syscalls-emulation-map.md`](docs/syscalls-emulation-map.md)),
guest behaviour is incomplete, and there has been **no adversarial security
review**. A guest is not a hardened trust boundary — do not run untrusted code
under it, and never describe it as "complete" or "production-ready."

---

## ⚠️ Rule 0 — codesign before you run on macOS / HVF

**Scope:** running guests on macOS uses the **`Hypervisor.framework` (HVF)**
path. A guest on that path only runs from a **codesigned** binary: a bare
`cargo build` strips the `com.apple.security.hypervisor` entitlement, so
`carrick run` dies with **`HV_DENIED` (`0xfae94007`)**.

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
| `just build-debug [ARGS]` 🔏 | Build + codesign with debug entitlements (`get-task-allow` for lldb attaching). |
| `just run [ARGS]` 🔏 | `just build` then run `target/release/carrick ARGS`. |
| `just check [ARGS]` | Fast **unsigned** `cargo build` — compile-check only, cannot run a guest. |
| `just test` | Host lib tests (no HVF/Docker). **Use the recipe, never a bare `cargo test --workspace --lib`** — `carrick-runtime`, `carrick-host` and `carrick-native-darwin` all fork from the test harness and deadlock when run in parallel, so the recipe runs every OTHER crate in parallel and then those three alone under `RUST_TEST_THREADS=1`. A per-module `TEST_LOCK` does **not** substitute: child reaping is PROCESS-wide, so a fork test in a sibling module can consume a stop/exit another module is mid-handshake with, and the rightful parent blocks forever (seen 2026-08-16 as an 11-minute `just test` hang at 0% CPU). |
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

Two conventions to keep in mind:

- **Use the `carrick-vmm-*` names for VMM crates** (`carrick-vmm-hvf`, not the
  historical `carrick-hvf`).
- **DSR translation & binary patching core**: `carrick-dsr` provides the
  platform-neutral traits and translation cache; `carrick-dsr-aarch64` and
  `carrick-dsr-x86` provide the ISA-specific decoder/emitter/translator engines;
  and `carrick-native-darwin` provides Darwin `MAP_JIT` and Tier-D binary
  patching primitives. These are preserved for future OS-level optimization.

### Where key subsystems live
- **Trap loop / syscall dispatch** — mature macOS trap loop in `crates/carrick-vmm-hvf/src/trap.rs`; x86 loop in `crates/carrick-x86/src/engine.rs` with backend adapters; dispatch in `crates/carrick-runtime/src/dispatch/mod.rs` (`SyscallDispatcher`, per-subsystem locks); syscall metadata in `crates/carrick-abi/src/syscall.rs` and guest-arch tables under `carrick-hal`.
- **VFS / rootfs** — `crates/carrick-runtime/src/dispatch/fs.rs`, `crates/carrick-runtime/src/vfs/` (in-memory OCI layer merge; `--fs host` cap-std backend — see [`docs/fs-host-capstd-amplification.md`](docs/fs-host-capstd-amplification.md)).
- **Memory / paging** — `crates/carrick-mem/src/memory.rs` (the mature VMM
  stage-1 identity map, EL0 trampoline and FEAT_PAN3 workaround; HVPatch differs
  below); mmap arena `crates/carrick-runtime/src/dispatch/mem.rs`.
- **HVPatch memory is non-identity.** Semantic guest VA, stage-1 IPA, reusable
  global-frame IPA and host-owner generation are distinct domains. Never feed
  one domain back into a lookup for another: authenticate through the live
  stage-1 translation and the exact current owner generation. Hidden mmap
  reservations are semantic metadata and materialize private backing on demand;
  do not restore a full per-mm 32 GiB physical/global-IPA arena or a VM-wide
  shared-zero COW source. Stage-1, stage-2 and frame-inventory publication form
  one rollback-capable transaction. Page-table coalescing additionally requires
  the output address to be aligned for the parent block; contiguous children
  alone are insufficient and masking an unaligned IPA silently maps the wrong
  bytes.
- **Signals** — `crates/carrick-runtime/src/dispatch/signal.rs` (Linux↔macOS signum translation, sigreturn trampoline).
- **Threads / futex** — `carrick-thread`; fork barrier
  `crates/carrick-vmm-hvf/src/fork_quiesce.rs`. HVPatch has one host pthread per
  logical guest thread but only a bounded, reclaimable set of HVF vCPU leases.
  Process-fork admission must win before waiting for a child-vCPU lease; fork
  participates in exec/exit cancellation; ordinary losing transactions lower
  to guest `EAGAIN`; and a selected long blocking wait releases its lease even
  when capacity appears spare before later waiters arrive.
- **epoll / sockets** — event backends in `carrick-host-bsd` (kqueue) and `carrick-host-linux` (epoll); sockets `crates/carrick-runtime/src/dispatch/net.rs` (synthetic `AF_NETLINK`, AF_UNIX path-hash registry).
- **ptrace / pty** — `docs/ptrace-darwin-design.md` (Phase 1 only); pty `crates/carrick-runtime/src/pty_relay.rs` + `interactive_supervisor.rs`, `vfs/devpts.rs`.
- **x86 / Rosetta** — `linux/amd64` images via Apple's in-guest Linux Rosetta (`docs/rosetta.md`).
- **Event ring (debug)** — always-on lock-free fork/socket/epoll ring
  `crates/carrick-runtime/src/event_ring.rs`, read via
  `scripts/carrick_lldb.py`. For HVPatch the authoritative ring and guest-thread
  census live in the VM carrier, not an outer namespace supervisor or detached
  file-authority helper.

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
- **A signed result belongs to one exact artifact.** Before calling a checkpoint
  or integration gate green, record source HEAD plus binary SHA-256, CDHash,
  LC_UUID, hypervisor entitlement and `__dof_carrick`; then run the full
  backend-specific probe set on that binary and prove scoped cleanup. Focused
  tests, `just ci`, or a 400/400 receipt from an earlier link do not qualify a
  later checkpoint. For HVPatch integration also smoke the still-shipped
  default/native lane; HVPatch remains opt-in until its own final default gate.
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
- **"No guest output" means "died before flushing" — never "did not run".** LTP
  writes its transcript to **stderr** under the new `tst_test` API and to
  **stdout** under the old one, so ALWAYS read BOTH `target/conformance/raw/
  <run-id>.err` and `.out`, with `grep -a` (they carry binary bytes). Old-API
  tests block-buffer stdout and only flush in `tst_exit()`, so an abort or a
  harness `SIGKILL` DISCARDS everything queued: a file containing only
  carrick's one-line `--user "root"` banner is a CRASH SIGNATURE, not an empty
  result. Recover the lost lines by re-running under a pty (`run -t`) or
  `stdbuf -o0`, and read the exit code (134 = abort, 139 = SIGSEGV). This cost
  several investigations a full cycle each before it was written down.
- **An inversion can mean the ORACLE is under-privileged, not that carrick is
  wrong.** The documented trap is a carrick false pass; the opposite direction
  is just as real and is easy to mis-file as a carrick gap. Twelve xattr suites
  were recorded as carrick gaps for months because they set `security.*`
  attributes, which need `CAP_SYS_ADMIN` — dropped by Docker's default cap set,
  so the ORACLE TBROKed with EPERM while carrick passed. Granting an oracle row
  the privilege its LTP `.needs_root`/`.needs_devfs` declaration implies (via
  `docker_flags`, as the fanotify and add_key rows already do) is the OPPOSITE
  of bending the gate to match carrick: it makes the oracle measure the Linux
  semantics the case was written to test. Confirm by running the case under
  Docker with and without the capability before changing anything.
- **Concurrent agents contaminate a conformance measurement — verify against
  UNMODIFIED main before believing a result.** Sibling agents running release
  builds and guests will make LTP cases fail identically and en masse; two hours
  were nearly lost chasing that as a code bug. The tell is that the SAME failures
  reproduce on a rebuilt unmodified base revision, so measure that pair rather
  than trusting one run. The harness helps: it self-classifies a starved timeout
  as `[starved]` versus a real `[blocked]` hang — read that field before filing a
  hang. Two related traps in the same family: a measurement run must use a binary
  REBUILT AFTER every merge it claims to cover (a stale `target/release/carrick`
  silently re-reports already-fixed failures — 28 of 126 gating failures in one
  run), and a suite must be invoked the way the HARNESS invokes it (wrapped in
  `/bin/sh -c` with `--max-traps` disabled) — a direct exec hangs as PID 1.
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
  (a box missing/with wrong images). Force a clean re-bless with
  `--refresh-oracle`. In particular, changing the contents behind a mutable
  image tag makes cached ecosystem rows non-authoritative even though they still
  hit: verify the live declared row population and image/binary digests, run the
  Carrick and Docker phases serially with `--refresh-oracle`, and machine-count
  every declared row.
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
  - **USDT/pid-provider tracing of a live native guest is ALLOWED** — carrick's
    own `carrick*:::` probes are the most direct instrument the native lane
    has, and refusing them left whole subsystems (the shared-translation store
    among them) measurable only by inference. Use `dtrace -Z` so probes in
    not-yet-started processes still arm. The one real hazard is **fasttrap
    detach**: an aborted session once leaked `SIGTRAP` into a continuing
    FreeBSD tracee and killed a live Kaniko build, so let a session end on its
    own rather than killing the consumer, and prefer kernel providers when the
    tracee is a long, unrepeatable run you cannot afford to lose.
  - **Declare perturbation.** A probe on a 2M-events/run path can double `sys`
    time; a script that perturbs must say so, and only same-instrument ratios
    are then citable.
- **When tracing perturbs a Heisenbug away, read the always-on event ring via
  `carrick-lldb`** — works live or from a core, with nothing pre-armed. Attach the
  **guest carrier** process, not the orchestrator parent (the parent's ring is
  empty). A raw/private-PID HVPatch run may contain an NsSupervisor, a VM
  carrier and a detached FileAuthority helper; ordinary `lldb run` follows only
  the outer process and can miss an abort in the carrier. Prefer
  `carrick debug lldb-run` or enumerate and attach child-first. The carrier alone
  owns the HVF VM, logical guest threads and authoritative event ring.
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
this bare in-process runner. USDT and pid-provider probes on a continuing
native process are permitted; the hazard to respect is **fasttrap detach**,
which once leaked `SIGTRAP` and killed a live Kaniko build, so prefer the
kernel-provider profiler (`sudo scripts/native-x86-profile.py PID`) when the
tracee is a long run you cannot afford to lose. **Never
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

**The two gates are ORDERED, and pathology is a correctness signal.** The
owner's ranking is explicit: reach 100% conformance first, then get within 2x of
Docker; going sub-1x is welcome but is never the thing to chase first. The
corollary is the useful part — **a pathological ratio is evidence of an INCORRECT
implementation, not merely a slow one.** When a suite runs 30-50x the oracle,
look for the wrong algorithm, not a tuning knob: `ltp-munmap04` at 47x and
`ltp-mmap18` at 34x COMPLETE, so they are not hangs — carrick is doing
structurally wrong work per operation. Treat that as a bug hunt with a
correctness fix at the end of it.

**Read a conformance perf ratio with the timeout budget in hand.** A hung suite
reports as spectacularly "slow" because it sits on its deadline: on the
2026-08-16 run the ten worst ratios (cpython-mmap 490x, context 297x,
tracemalloc 212x, ...) were all exactly 300.3 s — the suite budget — and a second
tier at exactly 30.5 s was LTP's own internal timeout. Excluding timeouts moved
the picture from a misleading 2.53x MEAN to a 0.94x MEDIAN, with 88.3% of suites
inside the 2x bar and LTP aggregating at 1.11x. So: fixing a hang removes a
"490x" row, and quoting the raw ratio of a timed-out suite as a performance
number is simply wrong. (That whole dataset also ran 8 workers on a 10-core
host, which makes every number contention-inflated and therefore a hypothesis,
never a controlled measurement.)

- **The overhead bar is WITHIN 2x of native-arm64 Docker** on the same workload.
  That is the number to rank against. As of 2026-08-01 the native lane was
  **~14.5x** on the cold go-build; **as of 2026-08-07** (the Move-3 campaign's
  closing refresh, after the anon-reuse-remap and stat-cache-interning fixes)
  the official shipped-default ratio is **10.1806x**
  ([`docs/perf-results/2026-08-07-post-move3-default-refresh.md`](docs/perf-results/2026-08-07-post-move3-default-refresh.md)),
  so reaching the 2x bar still means removing **80.36%** of current Carrick
  wall — every overhead bucket, not one of them. Rank work by whether it can
  plausibly be a multiple, and be honest that a 3-15% improvement does not
  move a double-digit ratio. Original evidence:
  [`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md`](docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md).
- **The build-lane CPU split, with the correction that supersedes it.** An
  earlier reading of the budget put carrick's own host userspace at 36.9% of CPU
  and inserted codegen at 18.6%, and that ranking was quoted here for months. It
  is WRONG and was corrected in place by
  `CORRECTION-user-module-split-codegen-IS-the-biggest-bucket` (`e63975d3`,
  `docs/perf-results/native-dsr-shape-census.jsonl`): 58% of user PCs matched no
  per-process JIT snapshot and were read as host code, when they were mostly
  JIT. Measuring instead with `umod(uregs[R_PC])` — any PC in no Mach-O image IS
  the `MAP_JIT` cache, so no snapshot join and no unwind is needed — gives
  **JIT 52.9% of total CPU, inserted codegen ~36.4%, carrick's own host text
  11.5% (+6.1% dylibs), kernel 29.5%, guest-shaped JIT words 16.5%.**
  So **emitted code is the largest bucket on the build**, and "carrick's own
  userspace has never been attacked" is worth about a third of what that reading
  implied.
- **Re-measured 2026-08-02 (supersedes the split above).** Sampling with the
  tracer's own pid excluded — `native-cpu-attribution.d` screened on
  `execname == "carrick"` and `carrick trace` runs libdtrace IN-PROCESS, so 54%
  of the old profile was the profiler — gives **user 67.6% / kernel 32.4%**, and
  within user **66.4% unsymbolized (the JIT cache), 13.3% carrick's Rust, 8.7%
  memcpy/memset, 7.8% malloc**. Emitted-code execution is **~45% of all build
  CPU**. The historical shape census put the DSR-overhead floor at **52.4% of
  executed emitted instructions, down from 81.3%**; current attribution uses
  the authenticated `carrick debug jit-shape-census` tooling. The historical
  residue was concentrated in ONE thing: slot 1128 is the
  guest's virtualized **x17** (physical x17 is the DSR edge register, borrowed to
  hold virtual branch conditions), and every such edge publishes it
  (`str x17,[x28,#1128]`) and restores it (`ldr x17,[x28,#1128]`). The general
  shape is `ctx-load64` 25.0% + `ctx-store64` 8.7% = **33.7% of executed emitted
  instructions ≈ 15% of total build CPU**. Histogrammed by (slot, register),
  that traffic is NOT general guest-register spilling — carrick keeps guest
  registers in host registers — it is carrick saving and restoring the four
  physical registers it BORROWS: **x17 ~21%, x19 ~9%, x15 ~3.3%, x16 ~0.2%**.
  There is no register-allocation problem; there is a stolen-register problem,
  and the borrow is gated on the emitter's own needs rather than on whether the
  guest value is LIVE. Note the ceiling:
  even PERFECT codegen leaves the build near 5x Docker, so the 2x bar needs the
  kernel and host-userspace buckets too.
- **The overhead workstream is still one thing: "utilize Darwin in the most
  efficient way to emulate Linux."** Carrick's host-side work and the kernel work
  it induces are not separate problems — they are the cost of LOWERING one Linux
  operation onto Darwin primitives, measured on the two sides of the syscall
  boundary. Rank by the **amplification factor
  of a single guest operation**, which is concrete and directly attackable
  where a CPU percentage is not:
  - guest `open` → **8.69 host opens** in-service-window on the **cold
    go-build** at HEAD (was 19.68 on 2026-07-28, before the trusted-dirfd
    lanes; total `openat`-window amplification 27.6x counting the
    resolution/mode tail, ~105 µs host kernel CPU per guest open). On the
    **fs-walk** fixture the same in-window figure is **2.37** (4.61
    counting every host `openat` in the run). Those are DIFFERENT WORKLOADS —
    pair like with like and do not read a ratio between them as progress.
    Full per-op ledgers:
    [`docs/perf-results/2026-08-06-build-lane-amplification-ledger.md`](docs/perf-results/2026-08-06-build-lane-amplification-ledger.md) (build),
    [`docs/perf-results/2026-08-05-fswalk-amplification-ledger.md`](docs/perf-results/2026-08-05-fswalk-amplification-ledger.md) (fs-walk);
    On fs-walk: whole fixture **2.05x** host per guest syscall (49,623/24,201,
    excluding 3,182 probable-tracer `kdebug_trace*`), 1.71x inside service
    windows. Still to drive toward 1: guest `openat` **5.91** host calls,
    `getdents64` **4.01** (of which six per directory are pure
    `fdopendir`/`closedir` preamble), `newfstatat` **2.86** — note the older
    "roughly one host call per guest stat" claim is true only of `fstatat64`
    itself. `close` (0.27) and `fcntl` (0.0009) are already below 1, so sub-1
    is reachable. **Open regression:** `carrick-only` `fstatat64` on this
    fixture went 32 (2026-08-02) → 5,802 (HEAD) with every guest-joined column
    flat — bisect that before starting a new fs lever;
  - guest `mmap(MAP_PRIVATE, fd)` → **lowered 2026-08-07** to a host
    `MAP_PRIVATE|MAP_FIXED` file mmap (was a `pread` of the FULL mapping
    length into fresh anon at `dispatch/mem.rs:2517`), default ON, hatch
    `CARRICK_MMAP_FILE_BACKED=0` (the sibling of `CARRICK_DSR_ZERO_REMAP`
    below). Fixes a real Linux divergence (private beyond-EOF SIGBUS), but
    its build-lane population is only 18 calls / 3.8 MiB/build — not the
    kernel-CPU lever this bullet originally named; see the fault-term
    correction below;
  - guest `execve` → WAS 4 full ELF materializations + 3 SHA-256 passes; the
    2026-08-02 exec lanes removed the payload hashing (metadata-only
    `ArtifactDigestCoverage`, hatch `CARRICK_EXEC_FAST=0`) and map eligible
    PT_LOADs `MAP_PRIVATE` from the executable's own host file (hatch
    `CARRICK_EXEC_FILE_BACKED=0`). What remains: the host self-re-exec's
    ~8.5 ms fixed chain, mostly Darwin's own exec floor
    (`docs/perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md`),
    and ONE remaining full read of the executable for loader planning.
    (Two prior claims here were stale and are corrected: `MAP_FIXED|
    MAP_ANONYMOUS` is already a single host mmap on the identity backend, and
    `map_prepared_for_plan` was live, not `dead_code`.)
  Drive each toward 1. **The fault term is dominated by CARRICK'S OWN host
  allocations, not the guest's memory.** The birth-keyed page census puts
  host-other at 63.2%/62.7% of sampled zfod (2026-08-03,
  [`docs/perf-results/2026-08-03-current-native-fault-ownership.md`](docs/perf-results/2026-08-03-current-native-fault-ownership.md)),
  re-confirmed at HEAD (63.26%/63.30%, the 2026-08-06 build-lane ledger —
  which also places 36% of all zfod inside guest `mmap` service windows).
  That in-window mass was 99.4% carrick's own **whole-range anonymous-reuse
  scrub** memsetting the ops' biased host backing — 98% of it serving
  hint-less `PROT_NONE` reserves that are provably zero already; it is NOT
  the guest touching its memory and NOT the eager `MAP_PRIVATE` file
  materialization (refuted 2026-08-06 by Task 5's population census: 18
  calls / 3.8 MiB per build)
  ([`docs/perf-results/2026-08-07-build-lane-fault-partition.md`](docs/perf-results/2026-08-07-build-lane-fault-partition.md)).
  **That scrub was replaced kernel-side on 2026-08-07** (`52342762`, hatch
  `CARRICK_DSR_ZERO_REMAP=0`): a fresh `MAP_FIXED|MAP_ANON` mapping now
  delivers the zeroed pages, collapsing in-window zfod 553k → ~723 and total
  build zfod by ~520k, retained on a −0.66 CPU-s (−3.2%) cold-build ABBA
  ([`docs/perf-results/2026-08-07-anon-reuse-remap.md`](docs/perf-results/2026-08-07-anon-reuse-remap.md)).
  The narrow 2026-07-29 claims
  survive (JIT first-touch 2.08% of zfod, inserted code 1.48%); that census's
  guest-dominates conclusion does NOT — it was superseded by the 2026-08-01
  audit and has been twice re-confirmed since. The remaining levers are
  allocation-side — buffer reuse / `MADV_FREE_REUSABLE` for the repeated
  ≥128 KiB buffers (the out-of-window 63% host-other mass) — as well as
  per-page cost.
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

- **Ask Darwin only for what Darwin owns.** Carrick has its own kernel now, so
  the host is the authority for real I/O and real hardware — files, sockets,
  memory, the time source, the CPU — and for nothing else. Identity (pid/tid/
  uid/gid/capabilities), process relationships, resource limits, the network
  NAMESPACE view, and signal delivery between guest processes are guest state and
  must be answered from the kernel graph keyed by the exact task. Delegating one
  of those does not return an approximate answer, it returns the HOST'S answer:
  `SCM_CREDENTIALS` handed guests the Mac user's uid/gid, the interface list
  handed them the Mac's `en0` IPv6, and guest DNS through host `getaddrinfo`
  dragged in fork-unsafe ObjC that aborted every forked child. Standing audit and
  the ranked fix list: [`docs/host-facility-boundary.md`](docs/host-facility-boundary.md).
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
- **That migration typed SCALARS and stopped there — the four domains it does
  NOT cover are where the HVPatch bugs live.** Populations (`kicker.count()` vs
  `task().threads().len()` are both `usize`, and there are EIGHT such sets),
  thread lifecycle ("alive" vs "can reach a safe point", which must be asked
  per-purpose), address-space ownership ("which mm" is not a value, it is
  `self`), and scope (a `static` carries no mark saying whether it describes the
  carrier or one Linux process). All four were TRUE statements under the retired
  one-process-per-guest model, so the code that relies on them still compiles,
  still passes, and still explains itself in terms of a model that no longer
  exists — three defects carry doc comments actively justifying the wrong
  behaviour. Critically, **every instance is correct while exactly one Linux
  process exists and wrong the instant a second appears**, and the smoke lane is
  a single `run-elf` process where carrier pid, root task id and `getpid()`
  coincide numerically — so the gate structurally cannot see this class, and a
  case exercising TWO live guest processes is worth more than any number of
  single-process cases. Evidence, the 42 audited sites, and the proposed
  architecture:
  [`docs/identity-and-scope-domains.md`](docs/identity-and-scope-domains.md).
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
- **Choose state authority by execution lane, not by host-process accident.**
  Native/VMM paths can fork real host processes, so state that must cross those
  forks cannot live only in a private `HashMap`; use durable/fork-coherent
  authorities such as xattrs, inherited fds or host-kernel bookkeeping. HVPatch
  guest `fork` stays inside one carrier, but the inverse trap applies: Darwin
  PID/process-owned state represents the carrier, not a logical Linux process.
  Put Linux process semantics in the kernel graph keyed by exact
  `TaskKey`/generation (or an explicitly shared description/namespace), never a
  process-global host PID, timer, ptrace session, classic lock owner or similar
  surrogate. Shared cross-lane code needs a typed backend authority rather than
  silently choosing either model.
- **Use the `libc` crate, not ad-hoc `extern "C"` blocks** (`libc::fork`,
  `waitpid`, `pipe`, `ioctl`, …). Exception: `applevisor-sys` raw `hv_*` bindings.

---

## Commits, hooks & CI

- **NEVER `git stash` in this checkout — the stash is REPO-GLOBAL, shared by
  every worktree.** Two agents in sibling worktrees collided on it: one's `git
  stash pop` restored the OTHER's entry into the wrong tree and dropped it from
  the list. It was recovered (a dropped stash survives as a dangling commit —
  `git fsck --no-reflog`, then `git stash store -m <msg> <sha>`), but only
  because someone noticed. Indices shift under you with no warning, so
  `stash@{0}` is never a safe handle. To set work aside, commit it on your own
  branch; to measure a "before", commit and then `git checkout` the base
  revision. Same class as the shared-working-tree `rsync` hazard above.
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
