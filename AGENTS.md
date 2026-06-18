# AGENTS.md

Operating manual for AI coding agents (and humans) working in **Carrick**. This
file is the index and the rulebook; depth lives in [`docs/`](docs/),
[`.agents/skills/`](.agents/skills/), and the [`justfile`](justfile). Read this
first, then follow the pointers.

> These rules were learned the hard way — each one is here because skipping it
> cost hours. They are not style preferences; they are load-bearing.

---

## What Carrick is

Carrick runs **unmodified Linux binaries on macOS / Apple Silicon as native
processes**, not as VM guests. Each guest *thread* gets its own
`Hypervisor.framework` (HVF) vCPU running the guest's own AArch64 instructions at
EL0; every `svc #0` traps into a host-side Rust translation layer that
re-expresses each Linux syscall as Darwin primitives. There is no guest kernel,
no second scheduler, no separate hypervisor RAM pool. The runtime is BKL-free
(per-subsystem locks, not a global lock).

**Status — experimental, not production-ready.** Be honest in code, comments,
docs, and commit messages: syscall coverage is partial (~210 emulated, ~130
deferred, several only partial — see [`docs/syscalls-emulation-map.md`](docs/syscalls-emulation-map.md)),
guest behaviour is incomplete, and there has been **no adversarial security
review**. A guest is not a hardened trust boundary — do not run untrusted code
under it, and never describe it as "complete" or "production-ready."

---

## ⚠️ Rule 0 — codesign before you run

A guest only runs from a **codesigned** binary. A bare `cargo build` strips the
`com.apple.security.hypervisor` entitlement, so every `carrick run` dies with
**`HV_DENIED` (`0xfae94007`)**.

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
| `just test` | Host lib tests (`cargo test --workspace --lib`; no HVF/Docker). |
| `just test-integration` | Host integration suites (`carrick-runtime`/`engine`/`image`; no HVF). |
| `just clippy` | `cargo clippy --workspace --all-targets -- -D warnings` (no-panic gate). |
| `just fmt` / `just fmt-check` | Apply / check formatting. |
| `just doc` | `RUSTDOCFLAGS="-D warnings" cargo doc` gate. |
| **`just ci`** | **Full local gate: `fmt-check → clippy → check → doc → test → test-integration`. Run this before every push.** |
| `just conformance-quick` 🔏 | Fast smoke regression vs the Docker oracle. |
| `just conformance [TIER]` 🔏 | Language/LTP conformance vs Docker (default tier `full`). |
| `just conformance-probes` 🔏 | Line-exact ABI probe gate vs Docker. |
| `just matrix` | Re-render [`docs/support-matrix.md`](docs/support-matrix.md). |
| `just kvm-smoke` / `just kvm-smoke-lima` | KVM backend smoke (real `/dev/kvm`, via lima from macOS). |
| `just install-hooks` | Install the git hooks (do this once per clone). |

**Toolchain:** pinned to Rust **1.96.0** ([`rust-toolchain.toml`](rust-toolchain.toml)),
**edition 2024**, resolver 2, workspace members `crates/*`. Workspace lints
**deny** `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` in
non-test code (tests are exempt via [`clippy.toml`](clippy.toml)); `release` has
`overflow-checks = true`. Note CI pins toolchain via `@stable` (moving), so a
freshly released stable can flag lints your local 1.96.0 doesn't — keep local in
sync with `rustup update stable`.

---

## Repository map

24-crate Cargo workspace under [`crates/`](crates/). Dependency direction:
`cli → engine → {image, runtime} → spec`. A HAL refactor
([`docs/hal.md`](docs/hal.md)) is splitting the runtime into platform-neutral
cores + per-OS backends so KVM/bhyve/NVMM can join HVF — hence the crate naming
(`carrick-vmm-hvf`, not `carrick-hvf`).

**VMM backends** (hypervisor impls over `carrick-hal`)
- `carrick-vmm-hvf` — macOS Hypervisor.framework backend; the mature one (trap loop, vCPU cluster).
- `carrick-vmm-kvm` — Linux/KVM backend (proves the HAL seam on real hardware).
- `carrick-vmm-bhyve` — FreeBSD/bhyve backend.
- `carrick-vmm-nvmm` — NetBSD/NVMM backend.
- `carrick-x86` — shared x86_64 VMM-backend engine scaffold.

**Host backends** (host-primitive impls)
- `carrick-host` — Darwin host-primitive helpers for the runtime.
- `carrick-host-bsd` — BSD-family (`cfg(carrick_bsd_family)`) impls of hal traits.
- `carrick-host-linux` — Linux host-OS glue (native epoll, etc.).
- `carrick-portable` — thin per-OS shim for raw `libc` symbols that differ/are absent across hosts.

**Core runtime & contracts**
- `carrick-runtime` — the core (~41k lines): ELF loading, syscall dispatch, VFS, fs backends, `execute(&RunSpec)`.
- `carrick-hal` — traits-only leaf crate, zero OS/hypervisor deps (hypervisor, errno, event, futex, sendfile, pty, host_info).
- `carrick-abi` — Linux AArch64 ABI constants + wire structs with compile-time size/offset/uniqueness asserts.
- `carrick-mem` / `carrick-guest-mem` — guest address-space construction (page tables, vectors, trampolines, ELF layout) / shared guest-memory hub types.
- `carrick-spec` — vocabulary nouns (`RunSpec`, `ContainerSpec`, `ImageConfig`, `Mount`, `NamespaceConfig`).
- `carrick-image` — OCI image acquisition + content store. `carrick-engine` — lowers a docker-style request into a `RunSpec`. `carrick-cli` — the `carrick` binary.

**Platform-neutral subsystem cores**
- `carrick-thread` — thread registry, private-futex park table, fork/page-table quiesce barriers.
- `carrick-signal-core` — neutral pending-signal bookkeeping. `carrick-timer-core` — interval/POSIX timer slots.
- `carrick-observability` — platform-neutral compat reporter (`compat-report`).

**Support:** `carrick-conformance` (harness), `carrick-test-support` (integration/CLI helpers, rootfs assembly).

### Where key subsystems live
- **Trap loop / syscall dispatch** — `crates/carrick-vmm-hvf/src/trap.rs`; dispatch in `crates/carrick-runtime/src/dispatch/mod.rs` (`SyscallDispatcher`, per-subsystem locks); syscall table `crates/carrick-vmm-hvf/src/syscall.rs`.
- **VFS / rootfs** — `crates/carrick-runtime/src/dispatch/fs.rs`, `crates/carrick-runtime/src/vfs/` (in-memory OCI layer merge; `--fs host` cap-std backend — see [`docs/fs-host-capstd-amplification.md`](docs/fs-host-capstd-amplification.md)).
- **Memory / paging** — `crates/carrick-mem/src/memory.rs` (stage-1 identity map, EL0 trampoline, FEAT_PAN3 workaround); mmap arena `crates/carrick-runtime/src/dispatch/mem.rs`.
- **Signals** — `crates/carrick-runtime/src/dispatch/signal.rs` (Linux↔macOS signum translation, sigreturn trampoline).
- **Threads / futex** — `carrick-thread`; fork barrier `crates/carrick-vmm-hvf/src/fork_quiesce.rs` (one pthread = one vCPU).
- **epoll / sockets** — Linux epoll onto Darwin kqueue (`crates/carrick-vmm-hvf/src/darwin_kqueue.rs`); sockets `crates/carrick-runtime/src/dispatch/net.rs` (synthetic `AF_NETLINK`, AF_UNIX path-hash registry).
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
  as insecure.
- **The Docker oracle is cached** (`scripts/conformance/oracle-cache.jsonl`) so
  routine gates run carrick-only. Single-run gating is non-deterministic
  (Go-under-HVF races); treat flaky flips as flakiness (retry / `known_gaps`),
  not regressions.
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
  change.** (1) Reduce to a minimal fast reproducer first — never iterate on the
  5-minute suite (a 90s repro turns each hypothesis into a tight loop). (2) Does
  **Docker** fail it too? Then it isn't carrick's bug. (3) Does the **pre-change
  binary** fail it? `git checkout <pre-session> -- <the files your commits
  touched>`, rebuild signed, re-run the repro — if it still fails, the bug
  predates your work (fix forward anyway, but you've cleared yourself). (4) Check
  the suite's **blessed baseline** verdict: a `carrick[Empty]`/TIMEOUT gating a
  suite the baseline had *completing* is a flake/timeout-under-load, not a content
  regression. (Worked example: the `cpython-socket` gating crash was a
  pre-existing `sendfile` partial-EAGAIN over-send, not the session's HVF work —
  proven by reproducing it on the pre-session binary.)
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

---

## Engineering standards

- **NEVER read Linux kernel or other GPL source when implementing carrick.**
  Clean-room only: derive ABIs from man-pages/specs and the differential Docker
  oracle (strace/observe behaviour, diff verdicts). This is non-negotiable.
  (Reading LTP *test* source — the oracle itself — is a separate, grayer matter.)
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

- **Conventional Commits: `type(scope): subject`** (imperative, lowercase, no
  trailing period). Types in use: `feat`, `fix`, `refactor`, `docs`, `test`,
  `diagnostics`. Real scopes: `bhyve`, `kvm`, `nvmm`, `runtime`, `conformance`,
  `hal`, `host`, `bsd`, `linux`, `abi`, `arch`, `portable`, `x86`. Scope is
  optional. End agent commits with a `Co-Authored-By:` trailer.
  - e.g. `feat(runtime): run x86_64 oci images on kvm`, `diagnostics(kvm): report registers on internal errors`.
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
