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
- **A cargo test executable is unsigned too.** The entitlement has to be on
  the process that calls `hv_vm_create`; for an in-process guest test that is
  `target/debug/deps/<crate>-<hash>`, which `just build` never touches. Guest
  tests in `carrick-embed` therefore run only through `just test-embed` →
  [`scripts/test-signed.sh`](scripts/test-signed.sh), which signs each test
  executable on the shipped binary's post-link path
  ([`scripts/lib/post-link-sign.sh`](scripts/lib/post-link-sign.sh)), runs
  them serially, and runs an unentitled negative control. `HV_DENIED` there is
  a FAILURE (`EmbedError::Entitlement`), never a self-skip — the
  `trap_hvf.rs` skip pattern is not to be copied.
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
| `just test-embed [ARGS]` 🔏 | Signed guest tests for `carrick-embed`: `cargo test --no-run`, sign each test executable with the hypervisor entitlement through the shipped post-link path (`scripts/test-signed.sh`), run under `RUST_TEST_THREADS=1`, then an unentitled negative control that must yield `EmbedError::Entitlement`. `HV_DENIED` is a failure, never a skip. Opt-in (HVF + `ubuntu:24.04`); deliberately **not** in `just ci`. |
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
- **New probe coverage belongs in `carrick-conformance-next`.** Generic probes
  run in-process through `carrick-embed` and compare against committed,
  source-hash-validated Docker oracle output. Do not add a new `carrick run`
  subprocess probe or invoke `carrick-cli --test conformance` as the routine
  probe gate. The only exceptions are the exact entries in
  `scripts/conformance/retained-generic-probes.txt`, the audited dedicated
  topology/service runners whose required embed APIs do not exist yet, and the
  single explicit CLI process-boundary contract. `just conformance-probes` is
  the public gate. `just lint-domains` runs
  `scripts/conformance/check-next-strategy.py` to reject subprocess execution
  inside `carrick-conformance-next` and direct legacy probe invocation in CI.
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
- **Probes are oracle instruments, not assumption encoders.** Report the errno
  NUMBER (`seek_data_negative_errno = errno`) rather than `errno == EINVAL`, so
  Docker names the answer (Linux said ENXIO where the worker assumed EINVAL;
  ESPIPE for `pwrite` on either pipe end where a worker "fixed" it to EBADF).
  A probe that passes on the pre-fix binary proves nothing — run it red first
  on that binary and record the false lines in the commit. A probe must never
  wedge the gate: bound every wait (`poll` with a 5 s cap) so a lost signal is
  a false line, not a hang. Libc-only probes cross-compile locally without
  Docker (`cargo build --target aarch64-unknown-linux-{musl,gnu}` inside
  `conformance-probes`, copy into `conformance-probes/target/<triple>/release/`)
  — the Docker phase is then only the bless.
- **Harness-driving traps that silently lie:** a `while read` loop that runs a
  guest consumes the loop's own stdin (redirect the guest's stdin from
  `/dev/null`); a `timeout` wrapper cannot be attached by lldb and its SIGTERM
  is ignored by a wedged CLI, so reap by `CARRICK_RUN_ID` instead; `just build`
  replaces `target/release/carrick` underneath any gate or run still using it —
  build only when no guest is alive. **A gate result belongs to exactly one
  binary**: rebuild after every merge you claim to cover.
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
- **Debug logging perturbs races; USDT does not.** `RUST_LOG=…=debug` on a
  bind/install path made a page-table race vanish in every run (the extra
  latency changed vCPU admission timing); the same lifecycle exposed as
  `carrick*:::stage1-arena-*` probes under `carrick trace -s
  scripts/dtrace/hvpatch-stage1-arena.d` reproduced it 2/3 and named the culprit
  in one trace. Instrument lifecycles (bind, install, replace, absent) as
  probes with the authority POINTER as an argument, so a recycled allocation
  address can be followed across its incarnations.
- **Per-task syscall flow is the hang instrument** (`hvpatch-guest-syscall-flow.d`
  keys on Linux pid/tid): "task N is parked in futex, task M in mmap for 5 s"
  reads directly. Two artifacts to know: `nanosleep` and `exit_group` emit no
  service-end record, so they always look parked; and the script stops at its
  45 s bound. For a wedged carrier, `sudo lldb -p <carrier> --batch -o "thread
  backtrace all"` on the CHILD of the CLI (the carrick binaries are attachable
  without a password; a `timeout` wrapper is not) shows every executor idle in
  a condvar when the guest is waiting for a wake that never comes.
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

These are the rules this project has paid for. Each one names the failure that
taught it; when you meet a new failure of the same shape, add it here, not to a
memory file.

### The two gates, in order

**Correctness first, then "zero" overhead — and a pathological ratio IS a
correctness bug.** Carrick's premise is running Linux binaries at host-native
cost, so a correct-but-slow runtime and a fast-but-wrong one are both dead ends.
The ranking is explicit: reach 100% conformance, then get within **2x of
native-arm64 Docker** on the same workload; sub-1x is welcome but never chased
first. The corollary is the useful part: a suite at 5x, 30x or 80x is not "slow",
it is doing structurally wrong work per operation (`munmap04` at 47x and
`mmap18` at 34x COMPLETE, so they were wrong algorithms, not hangs; `splice02`
at 37x was a false EOF that ended a copy loop early). Treat every such row as a
bug hunt with a correctness fix at the end, and rank work by the ledger's
ratio-to-Docker column. Read a ratio with the timeout budget in hand: a row
sitting exactly on its budget (300.3 s, 30.5 s) is a hang or a refusal, and its
"ratio" is meaningless. The dated numbers, the CPU split and its corrections,
the per-operation amplification ledgers and the fault-term attribution live in
[`docs/perf-results/overhead-campaign-narrative.md`](docs/perf-results/overhead-campaign-narrative.md);
the current shipped-default cold go-build ratio is **10.18x**
([`docs/perf-results/2026-08-07-post-move3-default-refresh.md`](docs/perf-results/2026-08-07-post-move3-default-refresh.md)).

**A perf claim is a hypothesis until it comes from a controlled, single-variable
experiment** on a quiet host (Apple Silicon cores are not homogeneous; a
concurrency sweep silently changes which cores run the work). Anything less is
written as "suggests", never "confirmed". Use Go's runtime as a dual-port oracle
for "what should this Linux idiom lower to on Darwin" (`mem_linux.go` vs
`mem_darwin.go`; BSD-licensed, readable): translate the guest's INTENT, not its
mechanism. Correctness is never traded for overhead — a guest-visible ABI
guarantee is immovable; find the lever that removes the work instead.

### Anything flaky is an architectural flaw

There are no "known gaps" and no retry-until-green. A verdict that differs
between runs, between load levels, or between `-v` and not `-v` is a design
error with a name waiting to be found — a lost wakeup, a wall-clock deadline
that turns scheduling delay into a guest-visible short read (the 50 ms foreign-mm
deadline), an authority that is correct with one process and wrong with two.
When a Linux semantic is unclear, read how a BSD-licensed kernel structures the
same path (FreeBSD's `pipe_write` is interruptible only at the sleep; carrick's
was checking signals before copying) and fix the shape, not the symptom.
Research the closest analogue first: FreeBSD's linuxulator, gVisor, NetBSD
compat, WSL1. GPL sources stay off-limits — clean-room only, ABIs from
man-pages, specs and the differential oracle.

### The compat zone is ours; the host is for what crosses the boundary

Carrick has its own kernel. **Functionality that never leaves the Linux compat
zone is implemented in it**: AF_UNIX sockets between guest processes, ptys a
guest creates, pipes, futexes, process groups and sessions, signal delivery
between guest tasks, identity (pid/tid/uid/gid/caps), resource limits, the
network-namespace view. A host fd, pty, socket or process is justified only when
the resource genuinely crosses into or out of the zone — a host file, a host
network connection, the CLI's own terminal, the CPU and the clock. Delegating an
in-zone object to Darwin does not return an approximate answer, it returns the
HOST'S answer (`SCM_CREDENTIALS` handed guests the Mac user's uid; a guest pty
backed by a host pty pair had no line discipline, so `^C` reached nobody).
Standing audit and the ranked fix list:
[`docs/host-facility-boundary.md`](docs/host-facility-boundary.md). Where the
host IS the right owner, prefer its native kernel mechanism (`sendfile`,
`kqueue`, `__ulock`) over a userspace reimplementation, through the `libc`
crate, not ad-hoc `extern "C"` (exception: `applevisor-sys`).

### A rule that lives in a comment is a bug that has not happened yet

**Typed domain values are the baseline** — a bare `u64`/`i32` never crosses a
semantic boundary (`Fd`/`HostFd`, `NsPid`/`HostPid`, `Signal`,
`GuestPtr`/`GuestLen`, `SigSet`/`SigBlockMask`/`WaitSigMask`,
`CanonicalNr`/`NativeNr`, `GuestVa`/`Gpa`/`HostVa`, `LinuxErrno`, `bitflags`
tables; named semantic constructors where polarity matters; `just lint-domains`
enforces the shipped bug shapes). That migration typed scalars and stopped, and
the next class of bugs lived exactly where it stopped: **ownership, scope and
lifetime**. Five separate defects in one day (2026-09-05) came from one
`Arc<Mutex<Option<PageTableManager>>>` whose rules — the arena source belongs to
the mm not the value, a vfork child shares the authority until its exec, a
rollback restores tables not ownership — existed only as comments, and every one
was violated by a clone, a `take()`, or a `strong_count` heuristic. **When a
defect class recurs because a rule is prose, replace the representation with a
type whose operations cannot express the bug** (`Stage1Authority` owning the
manager, its source and its share state), rather than patching sites; the owner
has explicitly licensed the bigger refactor for this. The same applies to
populations, "alive vs can-reach-a-safe-point", "which mm is self", and process-
vs-carrier scope — every one is true with one Linux process and wrong the instant
a second appears, and the single-process smoke lane structurally cannot see it,
so **a test with two live guest processes is worth more than any number of
single-process cases** ([`docs/identity-and-scope-domains.md`](docs/identity-and-scope-domains.md)).

### Authority follows the execution lane, never the host process

HVPatch keeps every Linux task in one carrier, so Darwin PID/process-owned
state describes the carrier, not a Linux process. Put Linux process semantics in
the kernel graph keyed by exact `TaskKey`/generation (or an explicitly shared
description), never a host pid, timer, ptrace session or classic lock owner.
Native/VMM lanes that fork real host processes need durable, fork-coherent
authorities (xattrs, inherited fds, host-kernel bookkeeping) instead of private
`HashMap`s. Shared cross-lane code takes a typed backend authority rather than
silently choosing a model.

### No shortcuts, no second paths, no dark launches

- **Fix the root cause.** A shell hack, a cheaper approximation, a gate excuse
  or a flag that hides a regression is not a fix.
- **Definition of Done = live-verified end-to-end**: clean build, passing tests,
  AND a runtime demonstration of the behaviour on the exact binary you claim.
- **No backward compatibility, no V2 beside V3, no shim, no deprecated
  spelling.** We are our own ecosystem; a second path costs every future
  measurement two answers.
- **Opt-OUT, not opt-in.** New work defaults ON with an exact `=0` hatch for
  bisection; a default-off mechanism is abandoned, not shipped. A mechanism
  measured worse is deleted (git remembers), not parked behind a flag. A test no
  gate executes is not a test (`carrick-cli` has no lib target; its in-file
  `mod tests` never run under `just test`).
- **Rust first; extend ourselves.** A new capability is a `carrick trace`
  profile or a `carrick debug` subcommand, not a standalone script. D scripts
  belong to a Rust profile that hashes them; Python only where lldb requires it.
  Everything else — capture, parsing, validation, statistics — is Rust under
  `-D warnings`.
- **Look for what exists before writing anything.** This tree has usually solved
  the adjacent problem; a second implementation is worse than a slightly wrong
  first one because now both drift.

### Directing workers is reviewing diffs, not reading reports

Isolated Antigravity worktrees do the code work; the director owns the runtime
fixes, the live verification and final acceptance. What this cost us to learn:

- **A worker's verdict is a claim.** `tests_passing: true` on a report whose diff
  does not compile, or whose contract is stale, has happened. Re-run the
  verification yourself in the worktree; land only what you read.
- **Grep the diff for files and behaviour outside the brief's fence.** One
  page-table worker also flipped `pwrite64` on a pipe read end from ESPIPE to
  EBADF, mentioned it in a bullet, and broke main for a day; a later worker then
  flipped the unit test to match it. Any behavioural change outside the fence
  needs its own oracle line before it lands.
- **A worker that dies on a transport timeout may leave a clean, fully tested
  diff.** Check `cargo check` and the tests in its worktree before assuming the
  work is lost; committing it yourself with the worker's trailer is faster than a
  fresh conversation. Long conversations die; brief narrowly and start fresh
  conversations on the same worktree.
- **Never `git merge --ff-only` from inside a worktree** (it merges into the
  worktree's own branch and reports success). Rebase there, fast-forward from the
  main tree, reconcile the line-pinned inventories on the CLEAN merged tree, then
  `just lint-domains`.

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
- **Line-pinned inventories are reconciled on a CLEAN tree, after the merge,
  before lint.** `scripts/migrate/reconcile-line-pinned-inventories.py` moves
  positions only; a row that truly retired (a host-pid lookup deleted) is
  dropped by hand from `host-authority-transition-inventory.json` with the
  reason in the commit. `check-host-authority-transitions.py --check` refuses a
  dirty tree with "authoritative compiler capture requires clean tracked
  snapshot inputs" — that is the tree, not the inventory.
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
