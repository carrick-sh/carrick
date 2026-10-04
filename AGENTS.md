# AGENTS.md

Index + rulebook for agents (and humans) in **Carrick**; depth in
[`docs/`](docs/), [`.agents/skills/`](.agents/skills/) and the [`justfile`](justfile). Each rule cost hours when skipped — load-bearing.

---

## What Carrick is

- Runs **unmodified Linux binaries as host-native processes** via a Rust syscall
  translation layer: no guest kernel, no second scheduler, no separate
  hypervisor RAM pool; BKL-free (per-subsystem locks).
- **HVPATCH** (`--exec-backend hvpatch`, default): Linux tasks, identity,
  address spaces, waits and signals live in Carrick's kernel graph, multiplexed
  in one VM carrier; guest `fork`/`clone` create **no** host processes.
- **Hosts:** macOS / Apple Silicon `Hypervisor.framework` (HVF) with AArch64
  guests is the release-quality reference lane; Linux/KVM, FreeBSD/bhyve,
  NetBSD/NVMM are additional hosts, x86_64 guests via the shared `carrick-x86`
  engine. Legacy 1:1 backends (`vmm`, `native`) are retired.
- **Status — experimental, not production-ready.** Be honest in code, docs and
  commits: partial syscall coverage (242 emulated, 95 deferred on the aarch64
  table — `grep -c 'SupportLevel::BringUp' crates/carrick-abi/src/syscall.rs`;
  several partial; [`docs/syscalls-emulation-map.md`](docs/syscalls-emulation-map.md)),
  incomplete guest behaviour, **no adversarial security review**. Not a
  hardened trust boundary — never run untrusted code; never say "complete" or
  "production-ready".

---

## ⚠️ Rule 0 — codesign before you run on macOS / HVF

Bare `cargo build` drops `com.apple.security.hypervisor` → `carrick run` dies
with **`HV_DENIED` (`0xfae94007`)**.

- **Build/run via `just build` / `just run`** ([`scripts/build-signed.sh`](scripts/build-signed.sh)
  re-applies `scripts/entitlements.plist`). `cargo build`/`just check` =
  compile-check only.
- **After changing `carrick-runtime`, rebuild `-p carrick-cli` and re-sign** —
  the lib alone doesn't relink `target/release/carrick`. Confirm:
  `strings target/release/carrick | grep <your-marker>`.
- **Test executables are unsigned too** — the entitlement must be on the
  process calling `hv_vm_create` (`target/debug/deps/<crate>-<hash>`).
  `carrick-embed` guest tests run only via `just test-embed` →
  [`scripts/test-signed.sh`](scripts/test-signed.sh) (signs via
  [`scripts/lib/post-link-sign.sh`](scripts/lib/post-link-sign.sh), serial,
  unentitled negative control). `HV_DENIED` there is a FAILURE
  (`EmbedError::Entitlement`), never a skip — don't copy `trap_hvf.rs`'s skip.
- **Never use `lld`** — strips `__DATA,__dof_carrick` → USDT empty →
  `carrick trace` fires zero events. Keep Apple `ld64`; verify
  `otool -l target/release/carrick | grep dof`.
- HEAD-only Homebrew tap (`brew tap carrick-sh/carrick && brew install --HEAD carrick`);
  the formula re-signs in `def install`.

---

## Commands

[`justfile`](justfile) is the source of truth (comments explain each recipe).
🔏 = codesigns (needed to run a guest).

| Command | Purpose |
|---|---|
| `just build [ARGS]` 🔏 | Build + sign release binary. |
| `just build-debug [ARGS]` 🔏 | Sign with debug entitlements (`get-task-allow`, lldb). |
| `just run [ARGS]` 🔏 | `just build`, run `target/release/carrick ARGS`. |
| `just check [ARGS]` | **Unsigned** `cargo build`, compile-check only. |
| `just test` | Host lib/harness tests (no HVF/Docker). **Never bare `cargo test --workspace --lib`.** Parallel `--skip serial_host`, then `serial_host` under `RUST_TEST_THREADS=1`; `scripts/migrate/check-serial-host-tests.py` ratchets it (host fork/spawn, env/rlimit/umask mutation, exact fs counters stay serial — reaping is process-wide). Per-crate serial reasons: justfile. |
| `just test-kernel [ARGS]` | VM-free inner loop: kernel lib + kernel-semantics suites. Still run `just test` + signed gates before push. |
| `just test-kernel-semantics [ARGS]` | `crates/carrick-kernel-example` suites; host-portable, CI runs them on Linux aarch64 (`kernel-linux-native`). |
| `just test-integration` | Host integration (`carrick-runtime`/`engine`/`image`; no HVF). |
| `just clippy` | `cargo clippy --workspace --all-targets -- -D warnings` (no-panic gate). |
| `just fmt` / `just fmt-check` | Apply / check formatting. |
| `just doc` | `RUSTDOCFLAGS="-D warnings" cargo doc`. |
| `just lint-domains` | Typed-domain semgrep gate ([`.semgrep/typed-domains.yml`](.semgrep/typed-domains.yml)). |
| **`just ci`** | **`fmt-check → clippy → lint-domains → deny → check-matrix → check → doc → test → test-integration`. Run before every push.** |
| `just conformance-quick` 🔏 | Smoke vs Docker oracle. |
| `just conformance [TIER]` 🔏 | Language/LTP vs Docker (default `full`). |
| `just conformance-probes` 🔏 | Line-exact ABI probe gate. |
| `just test-embed [ARGS]` 🔏 | Signed `carrick-embed` guest tests (see Rule 0). Opt-in (HVF + `ubuntu:24.04`), **not** in `just ci`. |
| `just matrix` | Re-render [`docs/support-matrix.md`](docs/support-matrix.md). |
| `just check-matrix` | Drift gate: matrix == fresh render of `baseline.jsonl` (deterministic, no run). |
| `just kvm-smoke` / `just kvm-smoke-lima` | KVM smoke (`/dev/kvm`, lima from macOS). |
| `just install-hooks` | Install git hooks (once per clone). |
| `just accept [ARGS]` | Run host and/or signed landing gate (no Docker). |
| `just accept --profile linux-portable` | Linux host gate + receipt; signed phase rejected. |
| `just remote-accept --ref COMMIT --phase host` | Worker gate on cloudmac + fetched receipt; also run signed for macOS/ARM changes. |
| `just lease MODE +CMD` | Run command under host flock lease (carrick shared, gate/docker exclusive). |

**Toolchain:** pin, edition, members, `deny`ed lints: [`rust-toolchain.toml`](rust-toolchain.toml) and
[`Cargo.toml`](Cargo.toml). CI uses moving `@stable`, which can flag lints
your pin doesn't — `rustup update stable`.

---

## Repository map

- **[`crates/README.md`](crates/README.md) is the crate map** (roles, product
  path `cli → engine → {image, runtime} → spec`, feature-closure rules).
  [`docs/hal.md`](docs/hal.md): platform-neutral contracts vs per-VMM/host
  impls, so KVM/bhyve/NVMM avoid HVF/applevisor.
- **Use `carrick-vmm-*` names** (`carrick-vmm-hvf`, not `carrick-hvf`).

### Where key subsystems live
- **Kernel semantics loop** — `crates/carrick-kernel-example` (scripted processes/threads on the public kernel API); [README](crates/carrick-kernel-example/README.md), [suite docs](docs/conformance-testing.md#kernel-semantics-suite).
- **Trap/dispatch** — `crates/carrick-vmm-hvf/src/trap.rs`; x86 `crates/carrick-x86/src/engine.rs`; `crates/carrick-kernel/src/dispatch/mod.rs` (`SyscallDispatcher`); metadata `crates/carrick-abi/src/syscall.rs`, arch tables in `carrick-hal`.
- **VFS** — `crates/carrick-kernel/src/dispatch/fs.rs`, mounts `crates/carrick-kernel/src/vfs/`, model `crates/carrick-vfs/src/` (OCI layer merge; `--fs host` cap-std: [`docs/fs-host-capstd-amplification.md`](docs/fs-host-capstd-amplification.md)).
- **Memory** — `crates/carrick-mem/src/memory.rs` (VMM stage-1 identity map, EL0 trampoline, FEAT_PAN3 workaround); mmap arena `crates/carrick-kernel/src/dispatch/mem.rs`.
- **HVPatch memory is non-identity:**
  - guest VA, stage-1 IPA, global-frame IPA and host-owner generation are distinct domains — never cross-feed lookups; authenticate via live stage-1 translation + exact owner generation;
  - hidden mmap reservations are metadata, backed privately on demand — no per-mm 32 GiB arena, no VM-wide shared-zero COW source;
  - stage-1, stage-2 and frame-inventory publication = one rollback-capable transaction;
  - coalescing needs the output address aligned for the parent block — contiguous children aren't enough; masking an unaligned IPA maps wrong bytes.
- **Signals** — `crates/carrick-kernel/src/dispatch/signal.rs` (signum translation, sigreturn trampoline).
- **Threads/futex** — `carrick-thread`; fork barrier `crates/carrick-vmm-hvf/src/fork_quiesce.rs`. Bounded executor pool with reclaimable vCPU leases: fork admission wins before waiting for a child lease; fork joins exec/exit cancellation; losers lower to `EAGAIN`; a long blocking wait releases its lease even if capacity looks spare.
- **epoll/sockets** — `carrick-host-bsd` (kqueue), `carrick-host-linux` (epoll); `crates/carrick-kernel/src/dispatch/net.rs` (synthetic `AF_NETLINK`, AF_UNIX path-hash registry).
- **ptrace/pty** — `docs/ptrace-darwin-design.md` (Phase 1); `crates/carrick-kernel/src/pty_relay.rs`, `crates/carrick-runtime/src/interactive_supervisor.rs`, `crates/carrick-kernel/src/vfs/devpts.rs`.
- **x86/Rosetta** — `linux/amd64` via in-guest Linux Rosetta (`docs/rosetta.md`).
- **Event ring** — always-on lock-free fork/socket/epoll ring `crates/carrick-kernel/src/event_ring.rs`, read via `scripts/carrick_lldb.py`; for HVPatch the authoritative ring and thread census live in the VM carrier.

---

## Conformance & the Docker oracle

Oracle = **native arm64 Docker Linux**, differential: fails in Docker too → not
carrick's bug. Skills: [`.agents/skills/ltp-conformance`](.agents/skills/ltp-conformance),
[`.agents/skills/carrick-trace`](.agents/skills/carrick-trace); wiring:
[`docs/conformance-testing.md`](docs/conformance-testing.md).

**Running**
- **Never run carrick and Docker concurrently** (VMs starve → wrong verdicts).
  Two-phase gate; `carrick‖carrick`/`docker‖docker` OK.
- **Machine quietness:** `just accept` holds the host lease in exclusive `gate`
  mode for its entire host/signed run; `scripts/test-signed.sh` holds shared
  `carrick` mode through build, signing, execution and scoped cleanup. Host
  tests/compilation compete for CPU and memory too. Both refuse `yes`, `stress`
  and `stress-ng`, reporting PIDs and parent commands. Deliberate load requires
  `CARRICK_ALLOW_LOAD=1`; logs record detected load and acceptance receipts
  include it. Contention fails explicitly after `HOST_LEASE_WAIT_LIMIT` (one
  hour), never skips. `CARRICK_HOST_LEASE_PATH` changes the lock file for tests;
  every participant on a gate host must use the same path. Never unlink a live
  lock file.
- **Lock order:** remote-accept checkout lock → host lease → build/test work.
  No host-lease holder may acquire a remote checkout lock. Nested signed runs
  inherit the gate's descriptor and reuse its exclusive lock without downgrade
  or reacquisition. Never upgrade a shared lease into a gate/Docker lease.
- **Stamp `CARRICK_RUN_ID`; reap with [`scripts/sudo/kill.sh`](scripts/sudo/kill.sh) `<run-id>`**,
  never `pkill -f carrick` (kills other lanes/worktrees). `timeout` wrappers can't be lldb-attached and a
  wedged CLI ignores SIGTERM.
- **A signed result belongs to one artifact.** Record HEAD + SHA-256, CDHash,
  LC_UUID, entitlement, `__dof_carrick`; run the full backend probe set on it;
  prove scoped cleanup. Earlier focused tests/`just ci`/400-of-400 receipts
  don't carry over. HVPatch integration also smokes the still-shipped
  default/native lane (HVPatch opt-in until its own final default gate).
- **Re-signing changes identity without relinking** (PID-bearing temp name).
  Keep the probe-tested artifact; use `just --no-deps conformance smoke` then
  `just --no-deps conformance full`, checking SHA/CDHash each rung. LC_UUID
  alone is insufficient.
- **Rebuild after every merge you claim** (stale binary: 28/126 gating failures
  in one run). `just build` replaces the binary under live runs — build only
  with no guest alive.
- **Invoke suites like the harness** (`/bin/sh -c`, `--max-traps` off); direct
  exec hangs as PID 1. `while read` loops: guest stdin from `/dev/null`.
- **Oracle is native arm64 only** — never a Rosetta `linux/amd64` container;
  ask the user for a native x86 box.
- **Cross-platform lanes:** `--lane kvm-local|bhyve-local|nvmm-local` (inject
  `--platform linux/amd64`, set `CARRICK_INSECURE_REGISTRIES`). Build off macOS
  with `cargo build -p carrick-cli --no-default-features --features platform-<linux|freebsd|netbsd>`
  (`platform-macos` → E0433; `build-signed.sh` is macOS-only). x86 excuses go
  in `baseline.kvm.jsonl`. No registry: `ssh -R 5005:<registry-host>:5005 <box>`.
  **Shared tree:** sync only your files, `md5`-verify deps — no blanket
  `rsync crates/`.

**Reading results**
- **No output = died before flushing, not "did not run".** Read BOTH
  `target/conformance/raw/<run-id>.err` and `.out` with `grep -a` (new
  `tst_test` API → stderr, old → stdout, flushed only in `tst_exit()`). Only
  the `--user "root"` banner = CRASH. Recover via `run -t` or `stdbuf -o0`;
  exit 134 = abort, 139 = SIGSEGV.
- **An inversion can be an under-privileged ORACLE** — twelve xattr suites
  were misfiled (`security.*` needs `CAP_SYS_ADMIN`; oracle TBROKed). Granting
  what `.needs_root`/`.needs_devfs` implies via `docker_flags` (like fanotify,
  add_key) is correct, not gate-bending. Confirm with/without the cap first.
- **Concurrent agents contaminate runs** — same failures on rebuilt unmodified
  main = contamination (~2 h nearly lost). Check `[starved]` vs `[blocked]`
  before filing a hang.
- **Missing ledger metadata ≠ never ran.** Audit row run IDs and both raw
  streams; preserve the original error/provenance gap — a supplementary diagnostic can't repair the ledger or confer
  acceptance.
- **LTP parity ≠ workload coverage** — no LTP case pushes `brk` past 4 MiB; a
  bhyve bug crashing 100% of cpython hid behind ~70% LTP. Rank by ecosystems
  (go/cpython/node, `--ecosystem`).
- **Attribute a REGRESSION before fixing:** does Docker fail it, does the
  pre-change binary, what did the baseline say? Sample bisect points ≥2×;
  suspect the PROBE first. Examples (`cpython-socket`, `expectcontinue`) in the
  ltp-conformance skill.
- **Syscall shape from `bpftrace` inside the oracle** (Docker-only phase),
  never guest `strace` (perturbs). Recipe in the ltp-conformance skill.
- Single-run gating is non-deterministic (Go-under-HVF); flaky flips are
  flakiness (retry / `known_gaps`), not regressions.

**Oracle cache** (`scripts/conformance/oracle-cache.jsonl`)
- Key = suite *declaration* (`OracleKey`: image, cmd, env, `docker_platform`,
  verdict…), not digest. Changing a determinant field invalidates every key →
  `0 cached oracle(s)`, full Docker pass, rewrite: **commit it** if on the
  canonical box with correct images, else `git checkout` it. Force:
  `--refresh-oracle`.
- Mutable image tag changed → cached ecosystem rows non-authoritative: verify
  row population and digests, run both phases serially with
  `--refresh-oracle`, machine-count every row.

**Probes**
- **New probes go in `carrick-conformance-next`** (in-process via
  `carrick-embed`, committed source-hash-validated oracle). No new `carrick run`
  subprocess probes or routine `carrick-cli --test conformance`, except
  `scripts/conformance/retained-generic-probes.txt`, audited topology/service
  runners lacking embed APIs, and the one CLI process-boundary contract. Gate:
  `just conformance-probes`; `scripts/conformance/check-next-strategy.py`
  (in `lint-domains`) enforces it.
- **Red-first:** `git checkout <pre-fix> -- <file>`, rebuild signed, DIFF;
  restore, MATCH; record false lines in the commit. Passing immediately proves
  nothing.
- **Report errno NUMBERS** (`seek_data_negative_errno = errno`) — Linux said
  ENXIO where EINVAL was assumed; ESPIPE for `pwrite` on either pipe end, not
  EBADF.
- **Bound every wait** (`poll`, 5 s) — a lost signal = false line, not a hang.
- Libc-only probes cross-compile locally
  (`cargo build --target aarch64-unknown-linux-{musl,gnu}` in
  `conformance-probes`, copy to `conformance-probes/target/<triple>/release/`); Docker is then only
  the bless.
- **Source hashes don't prove executable freshness** — rebuild both ARM64 libc
  probe sets, inventory and hash executables before reading diffs.
- Run `cargo test -p carrick-cli --test conformance conformance_probes` from the
  **repo root** (elsewhere: all lanes SKIP, `ok` in 0.04s). Logs need `grep -a`.

---

## Debugging

**Real debuggers, never `eprintln!`/shipped spam.** Guide:
[`docs/diagnostics-and-debugging.md`](docs/diagnostics-and-debugging.md).

- **`carrick trace` is THE tracer** (in-process libdtrace/USDT); extend it, no
  one-off `.d`. Auto-sudos; follow forks with `pid == target || progenyof(target)`;
  kill leftover runs; default guest `ubuntu:24.04` (frame pointers → stack
  walks). Skill:
  [`.agents/skills/carrick-trace`](.agents/skills/carrick-trace).
- **[`scripts/dtrace/`](scripts/dtrace/) scripts are durable** — named for
  their question, header states (a) what it measures, (b) live-qualified
  provider ABI facts, (c) perturbation. Never delete; record hard-won facts in
  headers.
- **`carrick trace` should fail closed on these traps:**
  - **Listed ≠ firing; FBT can't see local symbols** (`fbt::vm_fault:entry`
    never fires — trap path calls local `_vm_fault_internal`). Silent probe →
    check the KDK dSYM for a local twin
    (`nm -a …kernel.release.t8132.dSYM/…`, compare addresses). `handle_user_abort`/`arm_fast_fault`
    are FBT-blacklisted: sample, don't bracket.
  - **Frames can be symbolizer aliases** (`IORWLockUnlock` IS `lck_rw_done`,
    `IORWLockRead` IS `lck_rw_lock_shared`, `IOLockLock` IS `lck_mtx_lock`) —
    confirm by address. Addresses and details for both:
    [`docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md`](docs/perf-results/2026-08-01-native-wall-audit-and-fault-cost.md).
  - **Zero events = probe didn't fire**, never "didn't happen" — error out.
  - **`execname` scoping breaks across differently named arms** — key on
    carrick USDT lifecycle probes under `dtrace -Z`.
  - **Qualify provider ABIs live** (`sched:::preempt` absent on macOS;
    `vminfo:::as_fault` arg2 = exact 16 KiB page base).
  - **Live-guest USDT/pid tracing is allowed** (`dtrace -Z` arms future
    processes). Fasttrap detach once leaked `SIGTRAP` and killed a build — let
    sessions end on their own; prefer kernel providers on unrepeatable runs.
  - **Declare perturbation** (a 2M-events/run probe can double `sys`); cite
    only same-instrument ratios.
- **Logging perturbs races; USDT doesn't.** `RUST_LOG=…=debug` hid a
  page-table race (shifted vCPU admission timing); `carrick trace -s scripts/dtrace/hvpatch-stage1-arena.d`
  reproduced it 2/3 and named the culprit. Probe lifecycles (bind, install,
  replace, absent) with the authority POINTER as an argument to follow recycled addresses
  across incarnations.
- **Hangs:** `hvpatch-guest-syscall-flow.d` shows per-pid/tid parking
  (`nanosleep`/`exit_group` always look parked; 45 s bound). Wedged carrier:
  `sudo lldb -p <carrier> --batch -o "thread backtrace all"` on the CLI's
  CHILD (no password needed) — all executors in a condvar = lost wake.
- **Heisenbug → event ring via `carrick-lldb`** (live or core). Attach the
  **carrier**, not the parent (empty ring); a run may also have an NsSupervisor
  and FileAuthority helper, and plain `lldb run` follows only the outer
  process — use `carrick debug lldb-run` or attach child-first. Only the carrier
  owns the HVF VM, guest threads and authoritative ring. Skill: [`.agents/skills/carrick-lldb`](.agents/skills/carrick-lldb).
- **Deadlock → real CORE + `bt all`** (`sudo lldb -p <pid> -o "process save-core …" -o detach`);
  `sample`/`SIGQUIT` mislabeled fork-quiesce deadlocks. After `carrick_fatal!`
  read `CARRICK_LAST_FATAL` (`memory read` or `p CARRICK_LAST_FATAL`) for
  fatal domain and message.
- **Qualify the completed workload before optimizing** — service probes omit
  EL1/engine fast paths; CLI counters may cover only the wrapper (inotify09: 3M
  add + 3M remove watches, one host seek). Need live request/completion
  closure; counts ≠ critical path; keep uninstrumented A/B and native-I/O
  controls. `--profile hvpatch-inotify09-population` fits only that case.
- **Verify diagnoses empirically** — "race/coherence/Heisenbug" labels and
  memory notes are hypotheses; read real values, and check how you read them.

---

## Engineering standards

Add new same-shape failures here, not to memory.

### Guest-visible conformance contracts

In Carrick, guest-visible correctness includes Linux semantics and non-pathological operational complexity. Before planning or implementing any change that can affect guest-visible behavior or cost, use [`.agents/skills/carrick-conformance-contract`](.agents/skills/carrick-conformance-contract/SKILL.md), identify the applicable contract, and add one red-first when none exists. Prove semantics and deterministic work budgets in the cheapest capable layer, then complete the applicable signed gates. A semantic pass cannot excuse a structural-budget or runtime-ratio failure. Do not weaken budgets, add retries, increase timeouts, reduce concurrency, poll, or serialize symptoms as closure.

- Details: [`docs/conformance-contracts.md`](docs/conformance-contracts.md).

### The two gates, in order

- **Correctness, then ~zero overhead; a pathological ratio IS a correctness
  bug.** Target 100% conformance, then **≤2x native-arm64 Docker**; sub-1x is
  never chased first.
- 5x/30x/80x = structurally wrong work (`munmap04` 47x, `mmap18` 34x were
  wrong algorithms; `splice02` 37x a false EOF). Rank by ratio-to-Docker. A row
  on its timeout budget (300.3 s, 30.5 s) is a hang; its ratio is meaningless.
- Data: [`docs/perf-results/overhead-campaign-narrative.md`](docs/perf-results/overhead-campaign-narrative.md);
  cold go-build **10.18x** ([`docs/perf-results/2026-08-07-post-move3-default-refresh.md`](docs/perf-results/2026-08-07-post-move3-default-refresh.md)).
- **Perf claims need a controlled single-variable run on a quiet host**
  (heterogeneous cores; sweeps move work) — else "suggests", never "confirmed".
- Go's `mem_linux.go` vs `mem_darwin.go` (BSD) is a dual-port oracle: translate
  INTENT, not mechanism. Never trade an ABI guarantee for speed — find the lever that removes the work.

### Anything flaky is an architectural flaw

- No "known gaps", no retry-until-green. Run/load/`-v`-dependent verdicts are
  named design errors: lost wakeup, wall-clock deadline → short read (50 ms
  foreign-mm deadline), authority right for one process, wrong for two.
- Unclear semantics → study BSD-licensed prior art (FreeBSD `pipe_write`
  interrupts only at the sleep; carrick checked signals before copying):
  linuxulator, gVisor, NetBSD compat, WSL1 — fix the shape, not the symptom. **No GPL sources** — clean-room
  from man-pages, specs, the oracle.
- **A successful host rename isn't necessarily a move** (two hardlinks to one
  inode: both names survive). Keep the no-op distinct through backend, layered
  rootfs and dispatcher — a published move/whiteout hides or deletes a valid
  source. Namespace admission spans identity checks, host op and cache/event
  publication (stat snapshots don't substitute); archive admission first, with
  archive rollback and core-file publication in the same authority. Test
  physical names, cached lookup, a lower layer and `RENAME_NOREPLACE`.

### The compat zone is ours; the host is for what crosses the boundary

- **In-zone functionality lives in carrick's kernel:** guest AF_UNIX, guest
  ptys, pipes, futexes, pgrps/sessions, inter-task signals, identity
  (pid/tid/uid/gid/caps), rlimits, netns view. Host objects only for real
  crossings: host files, host network, the CLI terminal, CPU, clock.
- Delegating in-zone returns the HOST's answer (`SCM_CREDENTIALS` leaked the
  Mac uid; a host-pty-backed guest pty had no line discipline, `^C` went
  nowhere). Audit: [`docs/host-facility-boundary.md`](docs/host-facility-boundary.md).
- Host-owned → native mechanism (`sendfile`, `kqueue`, `__ulock`) via `libc`,
  not ad-hoc `extern "C"` (exception: `applevisor-sys`).

### A rule that lives in a comment is a bug that has not happened yet

- **Typed domains are baseline** — no bare `u64`/`i32` across a semantic
  boundary (`Fd`/`HostFd`, `NsPid`/`HostPid`, `Signal`, `GuestPtr`/`GuestLen`,
  `SigSet`/`SigBlockMask`/`WaitSigMask`, `CanonicalNr`/`NativeNr`,
  `GuestVa`/`Gpa`/`HostVa`, `LinuxErrno`, `bitflags`; named constructors where
  polarity matters; `just lint-domains`).
- Next frontier: **ownership, scope, lifetime.** Five defects on 2026-09-05
  came from one `Arc<Mutex<Option<PageTableManager>>>` whose comment-only rules
  (arena source belongs to the mm; vfork child shares until exec; rollback
  restores tables not ownership) broke via clone, `take()`, `strong_count`.
- **Recurring prose-rule defect → a type that can't express the bug**
  (`Stage1Authority` owns manager, source, share state), not site patches;
  owner-licensed.
- Populations, "alive vs can-reach-a-safe-point", "which mm is self",
  process-vs-carrier scope all break at two processes, invisible to the
  single-process smoke — **a two-live-process test beats any number of
  single-process cases** ([`docs/identity-and-scope-domains.md`](docs/identity-and-scope-domains.md)).

### Authority follows the execution lane, never the host process

- **A guest wait releases execution capacity** — never park a pool worker on
  another guest task. Return an owned continuation, even after partial I/O,
  keeping endpoint lifetime, byte offset and completion authority; restarting
  at zero corrupts streams, fake short writes aren't suspension. (32-writer
  pipe test: ten workers blocked in `write_pipe`, reader runnable, eight
  spares parked.) Test by exhausting the default pool; a bigger pool only
  moves the failure.
- Darwin process state describes the carrier. Linux process semantics key on
  exact `TaskKey`/generation (or an explicit shared description), never host
  pid, timer, ptrace session or lock owner.
- Lanes forking real host processes need durable fork-coherent authorities
  (xattrs, inherited fds, host bookkeeping), not private `HashMap`s; shared code
  takes a typed backend authority.

### No shortcuts, no second paths, no dark launches

- **Fix root causes** — no shell hacks, approximations, gate excuses or
  hiding flags.
- **Done = live-verified end-to-end**: clean build, tests, AND runtime demo on
  the exact binary.
- **No backcompat, V2-beside-V3, shims or deprecated spellings** — two paths =
  two answers forever.
- **Opt-OUT:** new work ON with an exact `=0` hatch; default-off = abandoned;
  measured-worse = deleted. Ungated tests aren't tests (`carrick-cli` has no
  lib target; in-file `mod tests` never ran under `just test`).
- **Rust first:** new capability = `carrick trace` profile or `carrick debug`
  subcommand; D scripts hashed by a Rust profile; Python only for lldb; the rest
  Rust under `-D warnings`.
- **Search before writing** — a second implementation is worse than a slightly
  wrong first (both drift).

### Directing workers is reviewing diffs, not reading reports

Worker worktrees (agy/codex) code; the director owns runtime fixes, live
verification, acceptance.

- **Verdicts are claims** (`tests_passing: true` on non-compiling diffs has
  happened) — re-verify in the worktree; land only what you read.
- **Grep diffs for out-of-fence changes** — a page-table worker flipped
  `pwrite64` on a pipe read end ESPIPE→EBADF, broke main for a day, and a later
  worker "fixed" the test to match. Out-of-fence changes need an oracle line.
- **Transport-timeout deaths may leave clean diffs** — check `cargo check` and
  tests; commit with the worker's trailer. Long conversations die: brief narrowly; start fresh
  conversations on the same worktree.
- **Never `git merge --ff-only` inside a worktree** (merges its own branch).
  Rebase there, fast-forward from main, reconcile inventories on the CLEAN
  merged tree, `just lint-domains`.
- **Linux workers run `just accept --profile linux-portable`, then `just remote-accept --ref <their commit> --phase host`** before reporting review-ready; macOS/ARM changes also require `--phase signed` coordinated with the director. Include both verdicts and receipt paths. macOS workers run `just accept`.

## Commits, hooks & CI

- **NEVER `git stash`** — repo-global across worktrees; a sibling's `pop`
  landed in the wrong tree and dropped the entry (recovery: `git fsck --no-reflog`,
  `git stash store -m <msg> <sha>`). Commit on your branch instead; for a
  "before", commit then `git checkout` the base. Indices shift silently —
  `stash@{0}` is never safe (same class as the shared-tree `rsync` hazard).
- **Subject: `type(scope): subject`** — imperative, lowercase, no period,
  ≤~72 chars. Types `feat`, `fix`, `refactor`, `docs`, `test`, `diagnostics`;
  optional scopes `bhyve`, `kvm`, `nvmm`, `runtime`, `conformance`, `hal`,
  `host`, `bsd`, `linux`, `abi`, `arch`, `portable`, `x86`. E.g.
  `feat(runtime): run x86_64 oci images on kvm`,
  `diagnostics(kvm): report registers on internal errors`.
- **Always a body** (one-liners only for typos/version bumps), ~72 cols,
  readable without the diff:
  - **Why** — root cause, Linux/host semantics, what broke for whom (never
    just "fix bug");
  - **What** — approach and any candid divergence from Linux;
  - **Verified** — probe/test/LTP case/oracle diff; name red-first probes;
  - `-` bullets for distinct parts; backtick symbols/paths.
- **Trailer:** `Co-Authored-By:` for the agent, after a blank line, e.g.
  `Co-Authored-By: Codex <codex@openai.com>`. Rewording another agent's
  commits: PRESERVE the author.
- **Inventories: reconcile on a CLEAN tree, post-merge, pre-lint.**
  `scripts/migrate/reconcile-line-pinned-inventories.py` moves positions only;
  drop truly retired rows from `host-authority-transition-inventory.json` by
  hand, reason in the commit. `check-host-authority-transitions.py --check`
  saying "authoritative compiler capture requires clean tracked snapshot
  inputs" means a dirty tree.
- **Hooks:** pre-commit `fmt-check`, pre-push `clippy`. **Never
  `--no-verify`** — `just fmt`. Unrelated fmt churn = toolchain skew:
  `git checkout` it.
- **CI is sequential** (`fmt → clippy → build → doc → test → integration`); an
  early red masks later failures — run full **`just ci`** after fixes.
- **ABI constants live in `carrick-abi`** — no column-0 `const LINUX_*`/`SYS_*`
  in dispatch; an un-imported `LINUX_*` match arm is a silent catch-all (watch
  for `unreachable pattern`).

---

## Where to look next

| Doc | Covers |
|---|---|
| [`README.md`](README.md) | Install, quick start, what's implemented. |
| [`docs/architecture-overview.md`](docs/architecture-overview.md) | HVF trap boundary, stage-1/FEAT_PAN3 paging, BKL-free concurrency. |
| [`docs/syscalls-emulation-map.md`](docs/syscalls-emulation-map.md) | Per-syscall fidelity + Darwin mechanism. |
| [`docs/diagnostics-and-debugging.md`](docs/diagnostics-and-debugging.md) | `carrick trace`, event ring + carrick-lldb, `carrick debug`, debug features. |
| [`docs/conformance-testing.md`](docs/conformance-testing.md) / [`conformance-coverage.md`](docs/conformance-coverage.md) | Running suites; probe→invariant map. |
| [`docs/support-matrix.md`](docs/support-matrix.md) | Generated verdict table (`just matrix`). |
| [`docs/hal.md`](docs/hal.md) | Multi-platform HAL plan. |
| [`docs/syscall-shim-design.md`](docs/syscall-shim-design.md), [`namespaces-design.md`](docs/namespaces-design.md), [`ptrace-darwin-design.md`](docs/ptrace-darwin-design.md), [`rosetta.md`](docs/rosetta.md) | Subsystem designs. |
| [`.agents/skills/`](.agents/skills/) | `carrick-trace`, `carrick-lldb`, `ltp-conformance`, `bifrost-trace-linux-guest`. |
