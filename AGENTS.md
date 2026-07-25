# AGENTS.md

Operating manual for AI coding agents (and humans) working in **Carrick**. This
file is the index and the rulebook; depth lives in [`docs/`](docs/),
[`.agents/skills/`](.agents/skills/), and the [`justfile`](justfile). Read this
first, then follow the pointers.

> These rules were learned the hard way — each one is here because skipping it
> cost hours. They are not style preferences; they are load-bearing.

---

## What Carrick is

Carrick runs **unmodified Linux binaries as host-native processes**, with a
hardware-virtualized vCPU per guest thread and a Rust syscall translation layer
instead of a guest Linux kernel. The mature default path is macOS / Apple
Silicon with `Hypervisor.framework` (HVF) running AArch64 Linux guests: every
`svc #0` traps to the host, and carrick re-expresses Linux syscalls as Darwin
primitives. There is no guest kernel, no second scheduler, no separate
hypervisor RAM pool, and the runtime is BKL-free (per-subsystem locks, not a
global lock).

The portability work splits that model across host/VMM and guest-ISA axes:
macOS/HVF, Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM, and active x86_64 guest
bring-up through the shared `carrick-x86` engine. Treat the macOS/HVF path as
the release-quality reference lane; treat non-macOS and x86_64 paths as active
bring-up unless the exact target-host gate proves otherwise.

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
- **The two native (DSR) drivers have exactly ONE wiring point.**
  `carrick-runtime/src/native_darwin.rs` and `src/native_freebsd.rs` route
  exclusively through `carrick-runtime/src/native/mod.rs` (`type HostNativeLane`
  resolves to `DarwinAarch64Lane` or `FreebsdX8664Lane`), plus its
  `native/fork_child.rs` shared post-fork dispatcher reset. Don't add a second.
  Seam design:
  [`docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md`](docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
  Phase 1 plan:
  [`docs/superpowers/plans/2026-07-23-native-lane-seam-phase1.md`](docs/superpowers/plans/2026-07-23-native-lane-seam-phase1.md).
  Phase 2 (separate plan) merges the two drivers' thread loops behind
  `NativeLane` and neutralizes `IdentityGuestMemory`/`NativeMapping` into an
  ISA-keyed identity-memory module.

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
