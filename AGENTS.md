# AGENTS.md

Index + rulebook for agents (and humans) in **Carrick**; depth in
[`docs/`](docs/), [`.agents/skills/`](.agents/skills/) and the [`justfile`](justfile). Each rule cost hours when skipped — load-bearing.

---

## What Carrick is

- Runs **unmodified Linux binaries** in one VM carrier per run, served by a
  small Carrick-owned guest kernel (ARM EL1 / x86 CPL0, one shared kernel
  crate set) and Rust services on the host. There is no Linux kernel, no
  second OS scheduler and no separate hypervisor RAM pool; the host side is
  BKL-free (per-subsystem locks).
- **HVPATCH** (`--exec-backend hvpatch`, default): Linux tasks, identity,
  address spaces, waits and signals live in Carrick's kernel graph, multiplexed
  in one VM carrier; guest `fork`/`clone` create **no** host processes.
- **Hosts:** macOS / Apple Silicon `Hypervisor.framework` (HVF) with AArch64
  guests is the release-quality reference lane; Linux/KVM, FreeBSD/bhyve,
  NetBSD/NVMM are additional hosts, x86_64 guests via the shared `carrick-x86`
  engine. Legacy 1:1 backends (`vmm`, `native`) are retired.
- **Status — experimental, not production-ready.** Be honest in code, docs and
  commits: partial syscall coverage (247 emulated, 89 deferred on the aarch64
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
  (`EmbedError::Entitlement`), never a skip. Any test that boots a VM is
  `#[ignore]`d and run only by a signed recipe (e.g. `just test-hvf-trap-engine`);
  never skip on a failed `hv_vm_create`.
- **Never strip or trim debuginfo** — release keeps `debug = true`; fix
  RAM-tight links with memory or lower link concurrency.
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
| `just worktree-gc [--apply]` | Census clean landed idle managed worktrees; `--prune-targets [--days N]` ages out idle Cargo intermediates through retained directory descriptors under gate/host and native Cargo locks. Unmanaged/busy checkouts are kept. Dry-run by default. See [build maintenance](docs/build-maintenance.md). |
| `just build-cache` | Shared per-host compiler cache stats; builds enable sccache by default, `CARRICK_SCCACHE=0` disables it. See [build maintenance](docs/build-maintenance.md). |
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
| **`just ci`** | **Full local gate (fmt, clippy, lint-domains, deny, matrix/layering checks, check, doc, test, integration; exact list in the justfile). Run before every push.** |
| `just conformance-quick` 🔏 | Smoke vs Docker oracle. |
| `just conformance [TIER]` 🔏 | Language/LTP vs Docker (default `full`). |
| `just conformance-probes` 🔏 | Line-exact ABI probe gate. |
| `just test-embed [ARGS]` 🔏 | Signed `carrick-embed` guest tests (see Rule 0). Not in `just ci`; runs in the merge queue on the self-hosted cloudmac lane. |
| `just matrix` | Re-render [`docs/support-matrix.md`](docs/support-matrix.md). |
| `just check-matrix` | Drift gate: matrix == fresh render of `baseline.jsonl` (deterministic, no run). |
| `just test-kvm` | Every `kvm`-lane test target (Linux x86_64, real `/dev/kvm`, `CARRICK_REQUIRE_KVM=1`: no skips). Lanes live in `[package.metadata.carrick.test-lanes]`; `test-lanes check` (in `lint-domains`) fails on a test target no gate runs. |
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
- **Memory** — `crates/carrick-mem/src/memory.rs` (guest VA layout, ELF loading, boot page tables and trampolines); mmap arena `crates/carrick-kernel/src/dispatch/mem.rs`.
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
  `carrick` mode through build, signing, execution and scoped cleanup.
  Owner decision [#231](https://github.com/carrick-sh/carrick/issues/231) /
  [#879](https://github.com/carrick-sh/carrick/issues/879) permits explicitly
  non-timing signed runs to set `CARRICK_SIGNED_FUNCTIONAL=1` for `functional`
  mode: at most three functional holders by default, configurable with
  `functional_limit` in `/etc/carrick/host-lease.toml` (or
  `CARRICK_HOST_LEASE_CONFIG`) and `CARRICK_HOST_LEASE_FUNCTIONAL_LIMIT`.
  Functional and shared carrick holders may coexist; gate/Docker exclude both
  and pending exclusive requests block new shared admissions. Acceptance,
  conformance and perf recipes clear the override and retain exclusive custody.
  Receipts record actual mode and total holder count at admission; this
  snapshot is not timing evidence. Functional custody cannot upgrade. Host
  tests/compilation compete for CPU and memory too. Both refuse `yes`, `stress`
  and `stress-ng`, reporting PIDs and parent commands. Deliberate load requires
  `CARRICK_ALLOW_LOAD=1`; logs record detected load and acceptance receipts
  include it. Contention fails explicitly after `HOST_LEASE_WAIT_LIMIT` (one
  hour), never skips. `CARRICK_HOST_LEASE_PATH` changes the lock file for tests;
  every participant on a gate host must use the same path. Never unlink a live
  lock file.
- **Contabo leases are per VM, never the whole hypervisor** (owner decision
  [#639](https://github.com/carrick-sh/carrick/issues/639), supersedes #565).
  KVM and agent clones use their in-VM lease; the standing controller takes no
  shared or exclusive physical-host custody. Broker config and its restricted
  SSH account are retired by the owner. Never restore a worker's disabled
  `/etc/carrick/host-lease.toml` to work around a test. See
  [Contabo setup](docs/ci/contabo-kvm.md#vm-local-leases-owner-decision-639).
- **Lock order:** remote-accept checkout lock → host lease → build/test work.
  No host-lease holder may acquire a remote checkout lock; never upgrade a
  shared lease into a gate/Docker lease; nested signed runs reuse the gate's
  lease and never downgrade or reacquire it. Supervisor custody, cleanup
  deadlines and known escape limits:
  [`docs/host-lease-containment-follow-up.md`](docs/host-lease-containment-follow-up.md).
- **Never pipe a gate through `tail`/`grep`/`head`** — the pipeline's status
  is the last stage's. Redirect or `tee` to a durable file with absolute
  paths and check the gate's own exit status.
- **Deliberate load and tracing clean up after themselves:** load runs inside
  the script that kills it (trap EXIT; receipts show `pgrep -x yes` empty);
  every `dtrace -Z` session is bounded and ends with `pgrep dtrace` empty.
- **Stamp `CARRICK_RUN_ID`; reap with [`scripts/sudo/kill.sh`](scripts/sudo/kill.sh) `<run-id>`**,
  never `pkill -f carrick` (kills other lanes/worktrees). `timeout` wrappers can't be lldb-attached and a
  wedged CLI ignores SIGTERM.
- **A signed result belongs to one artifact.** Record HEAD + SHA-256, CDHash,
  LC_UUID, entitlement, `__dof_carrick`; run the full backend probe set on it;
  prove scoped cleanup. Earlier focused tests/`just ci`/400-of-400 receipts
  don't carry over.
- **A signed verdict compares populations, not failure names.** A killed
  binary reports no failures (#344's watchdog cascade started 25 of 89 EL1
  tests and read clean): diff started tests and finished binaries against the
  main baseline too. Until #377 lands the receipt gate collapses `--nocapture`
  EL1 failures to one `step:el1-embed` key, already red on main, so EL1
  regressions read `NEW=0` (#352/#353); the director's local signed
  comparison is the EL1 gate meanwhile.
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
- A verdict that flips between runs is a defect, not noise: file it as a
  `flaky` issue with the run IDs and treat it as an architectural flaw (see
  "Anything flaky"). Never retry until green or add it to `known_gaps`.

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
- **Signed fixture bundles** are admitted by input identity, not by commit.
  Publish with `just fixtures-publish <SHA>` on a Linux host, then
  `just fixtures-restore <bundle>` / `just fixtures-verify <bundle>` on the
  Mac. Changed fixture inputs need a rebuilt bundle. Rules and receipts:
  [`docs/signed-fixtures.md`](docs/signed-fixtures.md#input-identity).
- **Report errno NUMBERS** (`seek_data_negative_errno = errno`) — Linux said
  ENXIO where EINVAL was assumed; ESPIPE for `pwrite` on either pipe end, not
  EBADF.
- **Bound every wait** (`poll`, 5 s) — a lost signal = false line, not a hang.
  Native oracle fixtures too: run under `timeout 10`, bound every blocking
  call, and `IPC_RMID`/`io_destroy` on every exit path.
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
- **Never lldb-attach to a process descended from the agent session's own
  terminal** (it crashed Terminal.app); attach from a separate shell or use
  `carrick debug lldb-run`.
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
- **Bad ELR far outside EL1 text, or "guest executed at EL1" at pool
  shutdown = ring stack overflow**, not a wild jump: the 16 KiB per-CPU EL1
  stack has no guard page, and by-value records on the exit chain
  (`publish_exit` alone 0x2190) overwrote a neighbour CPU's stack (#338). No
  large by-value locals or return values on EL1/CPL0 paths — box or borrow;
  frame-budget gate plus guard pages: #369.
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
- Data: [`docs/perf-results/overhead-campaign-narrative.md`](docs/perf-results/overhead-campaign-narrative.md)
  is **historical**: its figures (cold go-build 10.18x) measured the native
  lane removed in `f9933c9da`, and the `native-amplification` AMP1 profile
  records nothing on HVPatch (no `native_syscall_service_entry` call site).
  Don't cite them; the paired HVPatch baseline is #357, the ledger port #356,
  and `hvpatch-exit-attribution` is the profile to measure with (#363).
- **Perf claims need a controlled single-variable run on a quiet host**
  (heterogeneous cores; sweeps move work) — else "suggests", never "confirmed".
- **Perf A/B is paired and interleaved** (base/candidate on one host, same
  session); never diff against a stored baseline column. Complexity tests
  need adversarial rows (huge rows, mixed widths); run the affected ecosystem
  row standalone before landing a perf refactor.
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
- **No host readiness pipe for an in-zone object.** Carrick-owned waiters
  park on the object's wait queue and probe readiness once after enrolling
  (closes the lost-wakeup gap).
- **On a contained fast path only ENOENT is authoritative**; an errno a
  carrick-added flag could cause (e.g. `O_NOFOLLOW` → `ELOOP`) falls back to
  the resolving path.
- Host-owned → native mechanism (`sendfile`, `kqueue`, `__ulock`) via `libc`,
  not ad-hoc `extern "C"` (exception: `applevisor-sys`).

### A rule that lives in a comment is a bug that has not happened yet

- **Typed domains are baseline** — no bare `u64`/`i32` across a semantic
  boundary (`Fd`/`HostFd`, `NsPid`/`HostPid`, `Signal`, `GuestPtr`/`GuestLen`,
  `SigSet`/`SigBlockMask`/`WaitSigMask`, `CanonicalNr`/`NativeNr`,
  `GuestVa`/`Gpa`/`HostVa`, `LinuxErrno`, `bitflags`; named constructors where
  polarity matters; `just lint-domains`).
- **ABI records need aligned test storage.** A `Vec<u8>` promises byte
  alignment, not the alignment of EL1 records cast into it; Linux's allocator
  exposed non-unwinding misaligned-pointer failures hidden by macOS allocation.
  Fixtures use `carrick_test_support::TestEl1Region`, whose typed allocation
  and compile-time ABI alignment checks preserve the storage contract.
- **Scheduler fixtures own their CPU topology.** Set task affinity to the
  fixture's policy before cloning; inheriting host CPU counts can strand a
  bound executor on small hosted runners. Bound actor coordination waits.
- Next frontier: **ownership, scope, lifetime.** Five defects on 2026-09-05
  came from one `Arc<Mutex<Option<PageTableManager>>>` whose comment-only rules
  (arena source belongs to the mm; vfork child shares until exec; rollback
  restores tables not ownership) broke via clone, `take()`, `strong_count`.
- **Recurring prose-rule defect → a type that can't express the bug**
  (`Stage1Authority` owns manager, source, share state), not site patches;
  owner-licensed.
- Populations, "alive vs can-reach-a-safe-point", "which mm is self",
  process-vs-carrier scope all break at two processes, invisible to the
  single-process smoke — **a two-live-process (or two-live-thread) test beats
  any number of single-process cases** ([`docs/identity-and-scope-domains.md`](docs/identity-and-scope-domains.md)).
  Cover lifecycle exits: a non-last pthread's raw `exit` (every glibc/musl
  thread registers a robust list) and `exit_group` while a worker still runs
  were P0s no signed test exercised (#338).
- **Exit reserves topology, not a live participant's thread membership.** The
  exiting task, a child or an adopter can finish an already admitted EL1 birth
  or nonfinal exit while the graph is reserved. An owned participant transition
  accounts for those revision changes and retains topology-publication
  headroom; a captured broad revision or closing a live participant's gate is
  wrong. Test two live threads, late Born/ExitedInZone publication, drop and
  exhaustion.

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
- **Retirement and terminal decisions belong to the neutral owner**
  (`carrick_core::mm::retirement` today; `TerminalCustody` per #365).
  Backends apply verdicts and never re-derive eligibility: HVF re-deriving
  the pin-retirement predicate tripped
  `personality_boundary::pin_retirement_has_one_neutral_owner` (`668cbe01f`).

### No shortcuts, no second paths, no dark launches

- **Fix root causes** — no shell hacks, approximations, gate excuses or
  hiding flags.
- **Done = live-verified end-to-end**: clean build, tests, AND runtime demo on
  the exact binary.
- **No backcompat, V2-beside-V3, shims or deprecated spellings** — two paths =
  two answers forever.
- **Opt-OUT:** new work ON with an exact `=0` hatch; default-off = abandoned;
  measured-worse = deleted. Ungated tests aren't tests (`carrick-cli` has no
  lib target; in-file `mod tests` required explicit `--bin carrick` wiring in `just test` to run).
- **Rust first:** new capability = `carrick trace` profile or `carrick debug`
  subcommand; D scripts hashed by a Rust profile; Python only for lldb; the rest
  Rust under `-D warnings`.
- **Search before writing** — a second implementation is worse than a slightly
  wrong first (both drift).
- **Ring ports go through shared `no_std` `*-core` crates** (`carrick-pipe-core`,
  `carrick-fd-core`, `carrick-signal-core`, …) that the host dispatcher also
  consumes; no fresh ring-only copies (`rt_sigaction` existed three times,
  pipes twice; owner ruling 2026-10-13, #367).

### Directing workers is reviewing diffs, not reading reports

Worker worktrees code; the director owns runtime fixes, live verification,
acceptance.

- **Verdicts are claims** (`tests_passing: true` on non-compiling diffs has
  happened), and so are subagent and reviewer reports (one review cited
  nonexistent dead files, #368) — re-verify key claims in the worktree; land
  only what you read.
- **Every large or shared-kernel PR gets an independent review by a strong
  reviewer before landing.** Gates passed what review caught: two P0s in #338,
  forged two-task witnesses standing in for production operations in #331.
- **Grep diffs for out-of-fence changes** — a page-table worker flipped
  `pwrite64` on a pipe read end ESPIPE→EBADF, broke main for a day, and a later
  worker "fixed" the test to match. Out-of-fence changes need an oracle line.
- **Transport-timeout deaths may leave clean diffs** — check `cargo check` and
  tests; commit with the worker's trailer. Long conversations die: brief narrowly; start fresh
  conversations on the same worktree.
- **Workers base on GitHub main only** (`fetch https://github.com/carrick-sh/carrick`),
  never a host mirror (which lags). Rebase onto GitHub main at dispatch and
  before reporting review-ready.
- **After rebasing a fix stack across a code move**, list each fix as kept,
  ported or dropped and re-prove its red witness before any signed gate.
- **PRs that add or move files under `crates/`** must pass
  `just check-contract-change <main-sha> HEAD`. Never `git add -A` in a
  worktree (it commits the `conformance-probes/target` symlink).
- **Never `git merge --ff-only` inside a worktree** (merges its own branch).
  Rebase there, fast-forward from main, then run `just lint-domains` on
  the merged tree.
- **Worktree lifecycle:** remove the worktree and `target/` on every host when
  a PR merges (`git worktree remove --force <path>` and prune).
- **Workers prove their slice; the director gates the batch.** Workers run
  focused tests, `just clippy` and `just lint-domains` (plus scoped signed
  witnesses when they have HVF) and post the results on the PR. The director
  runs `just accept --profile linux-portable` and the signed gate once per
  stack, at the top PR's SHA, in a dedicated detached worktree, never in a
  worker's live worktree.
- **Routing:** a strong design-capable worker for shared-kernel, mm, fork,
  signal, carrier and seam work; a fast instruction-following worker for
  precisely specified mechanical work. A lane refused by one provider's
  content filter restarts fresh on the same worktree (WIP committed first)
  with a provider tier suited to systems work, never by rewording the retry.

### GitHub-first workflow

GitHub is the system of record for plans, status, decisions and evidence.
Chat, worker mailboxes, scratch notes and agent memory are not.

- **Write for people, not only agents.** Every comment, review, PR body
  and issue is read by humans too (owner direction 2026-10-24, #231). Lead
  with what happened and what it means for the reader. Use plain sentences,
  and explain or link terms of art and issue numbers. Put raw data (JSON
  contracts, logs, long tables) below that summary or in a collapsed
  `<details>` block. Agent-generated text follows the same rule:
  dispatch outcome comments and review bodies are written to be read.
- **Issue first, then work.** Every unit of work starts as an issue with the
  plan, acceptance criterion and links. Worker briefs cite the issue number,
  and the PR closes it (`Closes #N`).
- **Open a draft PR from the first commit**, linked to its issue, using
  `.github/pull_request_template.md`.
- **Board status follows every transition** on org project 1 ("Carrick shared
  kernel", which spans carrick and carrick-nt): Todo → In progress (dispatched)
  → In review (PR ready) → Done (merged or closed). Blocked names its blocker.
  Every new issue and PR goes on the board.
- **Decisions are recorded where they are made.** Owner decisions go in the
  decision-log issue (currently #231) and on the affected issue at the time
  they are made. Design passes are posted on their issue.
- **Progress, blockers and gate evidence are PR comments**: signed and
  portable receipts, A/B results, and the landing rationale. The next worker
  and the reviewer read them there.
- **Facts and defects are labelled issues** (`main-defect`,
  `false-fixture`, `flaky`, `lint-debt`, `follow-up`, plus lane and wave
  labels), with file:line on a named main SHA and an acceptance criterion.
  Search before filing; cite the issue number instead of re-deriving a fact.
- **Seams for out-of-tree personalities are carrick issues** in
  personality-neutral vocabulary (no NT names), labelled `seam`. carrick-nt
  links to them and pins carrick only at main merge commits.
- **One owner per hot file via [`.github/CODEOWNERS`](.github/CODEOWNERS)**;
  a second lane adds a layer to the owner's stack instead of carrying a copy.
- **Agent memory is not a rulebook.** A rule that every agent must follow
  goes in this file (or the skill or doc it points to); plans and status go
  on GitHub. Private agent memory holds only an agent's own working
  preferences and pointers. When a memory note turns out to be a project
  rule, promote it here in a PR and delete the memory copy.

### Multiple director sessions

When more than one director session runs at once, each one can break the
others through shared state they never see change. On 2026-10-21 that cost
a signed gate, nine hours of merge queue and a red `main` (#753).

- **Hosts are owned.** Each session uses only the hosts listed for it in
  the "Director lanes" comment on #231. Borrowing another session's host
  means asking first, and every gate still takes that host's lease.
- **Announce shared changes before and after.** This covers repository
  settings and rulesets, workflows and CI configuration, merges to `main`,
  the merge queue, Proxmox templates and the controller, and host-lease
  configuration. Send one message before and one after. The "after" message
  says how the other session would notice breakage. Test a ruleset against
  the merge queue itself, not only against human and App pushes.
- **A merge to `main` is announced at enqueue and at landing.** Name the
  PR, the merge SHA and the lanes to watch (signed EL1 for ARM work, KVM
  for x86). Announce a native stack layer by layer.
- **A main defect you cause is yours to announce.** File a `main-defect`
  issue and notify the other session immediately, so its red CI isn't
  misread as its own regression.
- **The record is on GitHub.** Session-to-session messages are
  notifications. The #231 "Director lanes" comment (owner, hosts, active
  PRs, in-flight shared changes) is the record, and each session updates
  its own section when its lane changes.

## Landing and personalities

- **Land through the merge queue** (`main-merge-queue`: rebase, all-green,
  `ci-ok` required). Cancel PR runs that won't land before enqueueing;
  hosted macOS capacity is scarce.
- **Dependent work is a native GitHub stack** (`gh stack`, #468), not a
  hand-built landing branch and not a wait-then-rebase chain. One branch and
  PR per independently reviewable layer, each under the size cap, with its
  own witness and issue link, and each PR based on the layer below. Fix a
  lower layer on its own branch, then `gh stack rebase` and `gh stack push`
  (force-with-lease). The director reviews every layer, runs the signed gate
  once at the top of the stack, and lands the stack with
  `gh stack merge <top PR>`: it enters the merge queue as one merge group and
  takes one HVF gate. Ejecting a layer ejects everything above it, so
  independent work stays in separate PRs. Stacks have no auto-merge.
  Workflow: [`.agents/skills/carrick-stacked-prs`](.agents/skills/carrick-stacked-prs/SKILL.md).
- **Lanes:** hosted Linux/macOS jobs in `ci.yml`. Heavy pull requests run the
  full macOS suite; same-repo PRs run it on the self-hosted `carrick-macos-ci`
  runners (a non-admin `ci` user on carrick-m4; #650), forks on hosted
  `macos-15`.
  Merge groups run `macos-build`, `macos-clippy` and `macos-authority`
  on hosted macOS as skew and compiler-authority checks;
  the nightly schedule reruns the full suite on hosted macOS. Since 137a177a22
  (2026-10-11), `ci.yml` has no push trigger. `kernel-runtime.yml` adds
  the self-hosted HVF lane (cloudmac, push to main and owner dispatch) and the
  KVM lane
  (self-hosted JIT clones on the Contabo host, `docs/ci/contabo-kvm.md`). The
  signed gate stays on cloudmac. Land on a failure-set diff against main
  (`NEW=[]`), not an absolute zero; `NEW=[]` is evidence only when every step
  is itemized and every binary finished (#352/#353, fix #377).
- **cloudmac is shared with CI** ([`docs/ci/mac-jit.md`](docs/ci/mac-jit.md)):
  JIT jobs run unprivileged beside the gates, so admit build-heavy work
  (`remote-accept`, gates) against running HVF jobs — an overlap on one
  volume killed both with ENOSPC; the gate worktree now has its own
  `carrick-gate` volume, CPU admission is still #376. Worktree admission keys on the
  checkout root's device+inode: never copy or cross-volume move an admitted
  checkout; remove and re-add it.
- **KVM evidence comes from the merge queue.** The `kvm-tests` lane produces
  a receipt and `kvm-gate` fails on NEW failures against the merge-group base.
  Do not run `just test-kvm` on the shared willow worker VMs; a targeted KVM
  test to debug a specific defect runs under `just lease gate`.
- **Personality split:** the shared kernel is personality-neutral. Linux is
  one personality (`carrick-personality-linux`); out-of-tree personalities
  build only on `carrick-personality-api`. Nothing in carrick names NT or any
  other out-of-tree personality. Personalities do not Forward: serve in ring
  or refuse. **Neutral crates must not depend on `carrick-personality-linux`**
  (`carrick-el1`, `carrick-core`, `carrick-x86-carrier` still do: #366/#237);
  per-task personality state is a ring-owned table keyed by `TaskKey`, Linux
  ids and lineage types move out of neutral crates, new seams use neutral
  vocabulary.
- **Ring-first:** every routed call is served exactly in ring or left
  unrouted (counted ENOSYS); a Forward-only arm is a second path. Changes to
  the crossing allowlist (`crates/carrick-personality-linux/src/crossing.rs`,
  `docs/design/arm-ring-first-flip.tsv`) need owner sign-off.
- **Fix in the shared layers** (shared kernel, `carrick-abi`, `carrick-hal`,
  neutral cores) so every backend benefits; no per-backend one-offs. Move
  code, never copy it.
- **Seams:** a seam is a carrick issue labelled `seam`, in neutral
  vocabulary. Additive personality-API seams (new types and traits, no
  guest-visible behaviour change, Linux dispatch/mm/fork/signal untouched)
  take the lighter gate: kernel-semantics, KVM/CPL0 builds and a signed
  smoke. Anything touching Linux paths keeps the full signed gate.
- **PRs are capped at about 4k changed lines** (owner, 2026-10-15). Larger work lands as
  independent slices, each with its own witness; exceptions need owner
  approval recorded on the PR (decision log #231).
- **No fake backends.** No in-memory or stub implementation of a service
  ships beside the real one; test doubles stay behind `cfg(test)` or a
  test-support crate.

## Commits, hooks & CI

- **NEVER `git stash`** — repo-global across worktrees; a sibling's `pop`
  landed in the wrong tree and dropped the entry (recovery: `git fsck --no-reflog`,
  `git stash store -m <msg> <sha>`). Commit on your branch instead; for a
  "before", commit then `git checkout` the base. Indices shift silently —
  `stash@{0}` is never safe (same class as the shared-tree `rsync` hazard).
- **Subject: `type(scope): subject`** — imperative, lowercase, no period,
  ≤~72 chars. Types `feat`, `fix`, `refactor`, `docs`, `test`, `diagnostics`,
  `chore`; optional scopes `bhyve`, `kvm`, `nvmm`, `runtime`, `conformance`,
  `hal`, `host`, `bsd`, `linux`, `abi`, `arch`, `portable`, `x86`, `ci`,
  `core`, `personality`, `arm`, `el1`, `ipc`, `xtask`. E.g.
  `feat(runtime): run x86_64 oci images on kvm`,
  `diagnostics(kvm): report registers on internal errors`.
- **Always a body** (one-liners only for typos/version bumps), ~72 cols,
  readable without the diff:
  - **Why** — root cause, Linux/host semantics, what broke for whom (never
    just "fix bug");
  - **What** — approach and any candid divergence from Linux;
  - **Verified** — probe/test/LTP case/oracle diff; name red-first probes;
  - `-` bullets for distinct parts; backtick symbols/paths.
- **Trailer:** one `Co-Authored-By: <Name> <email>` line per agent that wrote
  the change, after a blank line, spelled exactly `Co-Authored-By`. The name
  is the agent as its tool identifies it (model detail welcome, e.g.
  `Claude Opus 5.5`, `GPT-6.1 Sol`, `Gemini 4 Argon`). The email is the
  vendor's single noreply address, never anything else:
  `noreply@anthropic.com` (Claude), `noreply@openai.com` (Codex, GPT),
  `noreply@google.com` (Gemini, Antigravity). Human co-authors use their own
  address. Rewording another agent's commits: PRESERVE the author.
- **History rewrite, 2026-10-14:** every commit was rewritten once to
  normalize these trailers (trees unchanged). The old-to-new SHA map is on
  branch `history/coauthor-rewrite-2026-10-14`. Old SHAs quoted in markdown
  were remapped; those in code comments, D scripts and evidence files were
  left as historical provenance, so resolve them through the map.
- **Fix forward:** repair a bad landing with a follow-up commit; never
  `git revert` or reset main. Delete measured-worse code in a
  commit that cites the measurement.
- **No new line-pinned inventories or SHA-pinned receipts.** Retire existing
  ones into types, monotone counts or delete-at-zero, in the PR that zeroes
  them.
- **Authority debt:** `AuthorityDebtCeilings` counters may only decrease;
  `just lint-domains` checks them live. Local range checks must pass the PR
  base (`xtask authority-debt --base <merge-base>`); HEAD can't be compared to
  itself.
- **Hooks:** pre-commit `fmt-check`, pre-push `clippy`. Fix failures with
  `just fmt` / `just clippy`. `--no-verify` only with explicit owner approval
  recorded on the PR. Unrelated fmt churn = toolchain skew: `git checkout` it.
- **CI runs parallel jobs** across `ci.yml` and `kernel-runtime.yml`,
  aggregated by `ci-ok`. Locally, **`just ci`** (steps in the
  [`justfile`](justfile)) stops at the first red, which masks later failures —
  rerun it in full after fixes.
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
| [`.agents/skills/`](.agents/skills/) | `carrick-trace`, `carrick-lldb`, `ltp-conformance`, `carrick-bhyve-debug`, `carrick-conformance-contract`, `carrick-stacked-prs`. |
