# Ecosystem tests, hosted CI, fleet validation, and the amplification ratchet

**Date:** 2026-07-25 · **HEAD when written:** `ab9913f5` (working tree carries an
uncommitted `carrick-conformance` timeout-classification change — see §7.6) ·
**Status:** design + phased plan, nothing implemented.

**Method.** Every claim is tagged **[V]** verified in this session by reading
code at a cited `file:line` or running a command, **[E]** empirically established
by a prior run recorded in the discovery record, **[I]** inferred, or **[U]**
unknown. The resourcing decision turns on which is which; read the marks.

**Relationship to [`2026-07-25-strategy-assessment.md`](2026-07-25-strategy-assessment.md).**
That paper is the parent. It recommends *"Option C-scoped fused with B — make the
shipped default backend pass the project's own fast gate, and make the gate test
it by default,"* and its items 1, 2, 4 are prerequisites for most of this
document. This spec is the mechanism for items 1, 4 and 5 plus the CI substrate
they need. Where the two disagree, the strategy assessment wins; I found no
disagreement.

---

## 1. The premise, settled

### 1.1 The verdict

> **Hosted GitHub runners CAN execute real Linux guests — on macOS/arm64, through
> the native (DSR) backend, and nowhere else.** The macOS half of the maintainer's
> premise is true and was proven end-to-end. The Linux half is **false today**:
> there is no Linux native lane, so guest execution on hosted Ubuntu still needs
> `/dev/kvm` and `--exec-backend vmm`.

**[E] The decisive experiment.** A pristine `cargo build --release -p carrick-cli`
into a fresh target dir — never re-signed, `codesign -dvvv` reporting
`flags=0x20002(adhoc,linker-signed)` with **no `runtime` flag** and
`codesign -d --entitlements -` printing **no entitlement dict** — was run under a
`sandbox-exec` profile that denied `/Volumes/carrick`, from a case-insensitive
workspace, under `env -i`, with `ulimit -n 256`, and with `docker` absent from
`PATH`. Results, same binary, same environment:

| | result |
|---|---|
| `--exec-backend vmm` (control) | `hypervisor operation failed: operation not allowed by the system (error 0xfae94007)` |
| native (the **default** backend) | `hello from carrick`, rc=0 |
| `alpine:3.20`, pulled by carrick itself into an empty store | `ALPINE_OK / aarch64 / 0 / 3.20.10`, 1.06 s pull |
| `ubuntu:latest` | 391 binaries in `/usr/bin`; `echo\|tr\|sort\|tr` pipeline; `fork+exec OK`; 4.67 s incl. pull |
| `python:3.12-slim` | `PY_OK (3, 12, 13)`; subprocess spawned; threads OK; json OK; 5.5 s incl. pull |
| `golang:1.24` | `go build` + run a multithreaded program → `go build OK` (at `ulimit -n` ≥ 4096) |
| `node:24-slim` | `v24.18.0` |

**[E] Why `MAP_JIT` needs no entitlement.** An isolated C probe mirroring
`crates/carrick-native-darwin/src/jit.rs:41-58` (`mmap(PROT_RWX,
MAP_PRIVATE|MAP_ANON|MAP_JIT)` + `pthread_jit_write_protect_np` +
`sys_icache_invalidate`), built with plain `clang` and ad-hoc signed, executed
JIT'd code and re-executed it from a fork child. `com.apple.security.cs.allow-jit`
is consulted only **under the hardened runtime**; an ad-hoc/linker-signed binary
has the hardened runtime off, so it is never consulted.

**[V] Nothing in the native path reaches for HVF.**
`crates/carrick-native-darwin/Cargo.toml` depends on `carrick-dsr` + `libc` only.
The *binary* still links `Hypervisor.framework` (default features pull
`carrick-vmm-hvf`), which is harmless: the framework dylib ships on every macOS
and only the **entitlement** gates `hv_vm_create`.

**[V] The only entitlement carrick ever signs is HVF's.**
`scripts/entitlements.plist` contains exactly one key,
`com.apple.security.hypervisor`. `scripts/build-signed.sh` is therefore required
**only** for the VMM lane. The maintainer already truthed this up in AGENTS.md
Rule 0 (`046337c1`).

**[V] The default already points at the lane that works.**
`crates/carrick-cli/src/args.rs:178,360,470` —
`default_value = "native"`; `crates/carrick-spec/src/lib.rs:235-241` —
`enum ExecBackendRequest { #[default] Native, Vmm }`. A hosted job needs **no
flag**, no codesign step, and no secrets.

### 1.2 The Linux half of the premise is false

**[V]** `crates/carrick-runtime/src/page_profile.rs:124-140` is the native-lane
capability table and has exactly three arms — `(Macos, Aarch64)`,
`(FreeBsd, Amd64)`, `(NetBsd, Amd64)` — with a catch-all returning
`"no native execution lane for {os:?}/{isa:?} host; pass --exec-backend vmm to
request the platform VMM"`. `crates/carrick-runtime/src/native/mod.rs:87-95`
cfg's `HostNativeLane` to the same three. `ls crates/` shows
`carrick-native-{darwin,freebsd,netbsd}` and **no `carrick-native-linux`**.

⇒ On hosted `ubuntu-latest` / `ubuntu-24.04-arm`, a bare `carrick run` errors
out. **Any plan that says "native removes the virtualization requirement, so
Linux runners can run guests" is wrong.** Hosted Linux's value in this program is
Docker — native, non-emulated, on *both* architectures — for oracle production,
suite-image builds, and probe cross-builds. That is a large unlock, but it is not
guest execution.

### 1.3 The caveats a CI author must handle

Ranked by how badly they bite. Each is a design constraint below, not a footnote.

| # | Caveat | Evidence | Consequence for CI |
|---|---|---|---|
| **C1** | **`ulimit -n` is a hard blocker with lying errnos.** `go build` fails at 256/512/1024/**2048** and succeeds only at ≥4096. At 2048 it dies `runtime: epollwait on fd 4 failed with 24` (EMFILE) surfaced as `fatal error: runtime: netpoll failed`. The guest is told its limit is 1048576 and cannot adapt. | **[E]** single-variable flip, all else held constant | Every guest step **must** raise the cap. `HOST_INTERNAL_FD_MIN_FALLBACK = 2048` (`crates/carrick-host/src/internal_fd.rs:21-27`, commented "CI runners with a low fd cap stay green") was sized against **unit tests** and is **not** sufficient for guest workloads. |
| **C2** | **No wall-clock bound exists on the native lane.** `CARRICK_MAX_WALL_MS` and the progress-aware watchdog live only in `crates/carrick-runtime/src/vcpu_loop/mod.rs` (VMM path). `DEFAULT_MAX_TRAPS` was **removed** in `8d9139be`. | **[E]** `grep` for `max_wall\|MAX_WALL` over `native_darwin.rs` + `native/*.rs` → zero hits | A stuck native guest runs to GitHub's 6-hour job cap. Every guest step needs an external bound. The conformance harness already supplies one per suite (`engine.rs` `run_one` + scoped kill); a hand-written `carrick run` step does not. |
| **C3** | **`cat` of a non-empty file loops forever on ubuntu:26.04 — on BOTH backends.** Re-adding `--max-traps 1000000` yields rc=137 with 1.2 MB of `Mac\|Mac\|Mac…`: the guest re-emits the file forever. Not native-specific, not hosted-specific. busybox `cat` is fine; `head`/`dd`/`cp` are fine; piping to `head -1` terminates (SIGPIPE). | **[E]** | An EOF/offset bug. Combined with C2 this is the #1 CI hazard: `8d9139be` converted a diagnosable abort into an unbounded hang **and** unbounded stdout. Do not seed any ecosystem test with `cat`. |
| **C4** | **Node `worker_threads` fails on native**: `DSR cannot emit constrained writeback load overlaps its base register LDP 0xa8c17ff1`. `node -v` works; the same workload on `--exec-backend vmm` returns `NODE_OK v24.18.0 arm64`. | **[E]** | A native-lane translator gap. A node ecosystem test would be **red on arrival**. |
| **C5** | **The conformance harness hard-refuses an unentitled binary on the native lane.** `crates/carrick-conformance/src/main.rs:357-368` routes `Lane::MacosNativeDsr` into the same `else` arm as `Lane::Hvf` → `preflight()` → the codesign check at `main.rs:1588-1593`, whose message ("run `just build`; every guest run would be HV_DENIED") is **factually false for the lane it blocks**. | **[V]** | **One `if` stands between the harness and a hosted runner.** Compounded: `justfile:208` `conformance-native … : build` depends on the signing recipe. |
| **C6** | **`cargo test -p carrick-cli --test cli` silently UN-SIGNS `target/release/carrick`.** A later `--exec-backend vmm` step then fails HV_DENIED with the "signed" binary. | **[E]** | AGENTS.md Rule 0's footgun, fired from a *test* command. A job running both a cargo test target and a VMM step must `just sign` in between. |
| **C7** | **39 of 63 `carrick-cli --test cli` tests are RED at HEAD** (all `run_elf_command_drives_*_static_fixture`), because `run-elf` JSON on native reports `"stdout": ""`, `"traps": 0` while `--raw` delivers real bytes. **No CI job runs this target.** | **[E]** | Assertions must use `--raw`/exit codes, **never** the CLI's JSON `stdout`/`traps`. `RunResult.traps`/`report` are hardcoded stubs on the native path (`crates/carrick-runtime/src/native_darwin.rs:1612-1613` — **[V]** `traps: 0, report: CompatReport::default()`). |
| **C8** | **Case-insensitive scratch degrades silently, never fails.** `crates/carrick-runtime/src/apfs.rs:290-313` prefers `/Volumes/carrick` iff `is_dir() && probe_case_sensitive()`, else falls back; `apfs.rs:322-326` returns `Host` unconditionally on a stock build. | **[E]** | Hosted runners boot case-insensitive APFS. Go source trees and `node_modules` are exactly where path-case collisions bite. `carrick volume create` exists (`args.rs:786-800`) but **[U]** whether `diskutil apfs addVolume` works inside a hosted runner VM. |
| **C9** | **Disk is the binding constraint, memory is not.** Peak RSS for a minimal ubuntu guest = 61.8 MB. `~/.carrick` reached 1.9 GB after 5 stock images; the cargo target dir is 1.3 GB; the runner SSD is 14 GB. Scratch **leaked 1.4 GB despite `--rm`** on SIGKILLed runs. | **[E]** | The four conformance images (go 1.2 GB, node 1.7 GB, ltp 690 MB, cpython 435 MB *compressed*) will not co-exist with a target dir on 14 GB. Jobs must purge scratch between steps. |
| **C10** | **No HVF-free macOS build exists.** `cargo check -p carrick-cli --no-default-features --features syscall-shim` → 276 errors. | **[E]** | You cannot *prove by feature closure* that a hosted macOS job never touches HVF. Harmless in practice (§1.1) but it forecloses `scripts/closure-assert-no-hvf.sh`-style assurance on this lane. |
| **C11** | **Every hosted pull is anonymous.** carrick logs `uses a credential helper, which is not supported yet; pulling anonymously`. | **[I]** | Docker Hub's per-IP anonymous rate limit applies to shared runner egress. Mitigate via GHCR or `carrick login` (Basic auth from a config.json is supported — `crates/carrick-image/src/auth.rs:85-125`). |

### 1.4 What must still be proven by an actual CI run

These could not be settled locally. **Everything in §3 rests on item 1.**

1. **The macOS *version* delta — the single biggest unknown, and it is already
   breaking CI.** **[E]** The two tests failing on GitHub's `macos-14`
   (`crates/carrick-host/src/host_proc.rs:960`,
   `direct_vm_reservation_tests::{canonical_dyld_delegated_empty_tuple_is_accepted,
   fork_child_canonical_unnested_dyld_gap_is_accepted}`) **pass locally even under
   every hosted constraint that could be imposed** — `7 passed; 0 failed` under
   `sandbox-exec` + `ulimit -n 256`. So it is not fd limits, not the scratch
   volume, not the entitlement. It is the one variable that cannot be simulated:
   **macOS 27 / `Mac16,12` locally vs macOS 14 / M1 there.** The tests hardcode
   host VA `0x4_0000_0000`; locally `mach_vm_region` reports a 16 GiB hole below a
   384 GiB reserved region at 64 GiB, so the address classifies as
   `DelegatedDyldPmapEmpty`; on macOS 14 the layout differs and it classifies as
   `Reserved(...)`. **This is native-backend fixed-VA code, and only the hosted
   runner exposes it.** It is simultaneously the best argument for this program
   and a hard blocker for it.
2. **Whether the native lane itself runs on GitHub's macOS image.** Everything in
   §1.1 proves it runs on macOS 27. Given (1), the DSR/identity-memory
   fixed-address assumptions must be re-proven on the hosted image by a real run.
3. **3 vCPU / 7 GB wall-clock.** Local timings are from a 10-core/32 GB machine
   and are lower bounds. The `macos-native-dsr` lane already carries
   `timeout_scale 5.0`; **[U]** whether that suffices on 3 cores.
4. **`diskutil apfs addVolume` / `hdiutil` inside a hosted runner VM** (C8).
5. **`/dev/kvm` on hosted `ubuntu-latest`** (and its absence on
   `ubuntu-24.04-arm`). **[I]** from the 2024-04-02 GitHub changelog on Android
   hardware acceleration; the standard enabling step is a
   `99-kvm4all.rules` udev drop-in. Settle with a throwaway workflow doing
   `ls -l /dev/kvm` before any design depends on it.
6. **Whether 14 GB survives a real suite set** (C9).
7. **`just test` / `just test-integration` wall-clock on the hosted image.**

**Ruling this forces:** pin **`macos-15`** (or `macos-26`), never `macos-14`
(deprecated upstream) and **never** `macos-*-intel` / `macos-*-large` — those are
x86_64 with 4 KiB pages, and `page_profile.rs:143-170` returns `Unsupported`
unless `host_page_size == 16384`. And fix `host_proc.rs` to **derive** its probe
VA rather than hardcode `0x4_0000_0000`.

---

## 2. What I am NOT recommending, and why

Stated first, so the design below is read as a set of deliberate exclusions.

1. **NOT a fleet orchestrator.** A runner that *executes* across hosted CI + the
   self-hosted Mac + the willow KVM box + the bsdvm guests is the wrong artifact.
   Four transports already exist and differ irreducibly: `scripts/bsdvm.py`
   (1790 lines of QEMU-serial + pinned known_hosts + boot-retry), `limactl shell`
   wrapped in `sg kvm -c`, plain LAN ssh, and the GH API. A fifth orchestrator
   adds credential surface (GH tokens *plus* fleet ssh keys in one place, in a
   project with **no adversarial security review**) and violates the blast-radius
   rule AGENTS.md already encodes (never `pkill -f carrick`) at scale. **Take the
   join key and the aggregator; leave the transports alone.**
2. **NOT ecosystem-scale workloads as cargo integration tests.** The in-process
   OCI entry `native::run_oci_native` (`crates/carrick-runtime/src/native/mod.rs:151-207`)
   is `pub(crate)` and takes a fully-built `SyscallDispatcher`, a resolved
   `ExecutionPlan`, and a path inside an already-materialised rootfs. Reaching it
   from a test means re-implementing image resolution, layer merge, scratch
   selection, network seeding, and pid-ns init — i.e. a worse copy of
   `carrick-conformance`, which already runs those workloads Docker-free. That
   would violate "no pragmatic shortcuts."
3. **NOT publishing the four conformance images as a phase-1 prerequisite.** They
   live only in `localhost:5050`/`localhost:5005` and total ~4.7 GB of blobs.
   Publication is worth doing eventually, but the ecosystem-test format below
   sidesteps it entirely by carrying test source **inside** the suite `cmd` on a
   digest-pinned **public** base image — a pattern `go-build` already uses
   (`scripts/conformance/suites.toml:7-16`).
4. **NOT regenerating the arm64 Docker oracle on hosted Ubuntu.** Hosted `dockerd`
   is a different kernel from Docker Desktop's LinuxKit VM, and
   `crates/carrick-cli/tests/conformance.rs` already records cases where "the
   ORACLE is the limited side: Docker Desktop's LinuxKit kernel." Switching oracle
   hosts **will** move verdicts on 2,127 legacy suites. Scope the hosted oracle
   producer to the **new ecosystem manifest only**; never let it touch
   `baseline.jsonl`.
5. **NOT the full 2,127-suite tier on hosted runners.** **[E]** the arm64 oracle
   cache records 44.4 min of Docker-serial work; carrick is 13.5× on go-errors and
   >25× on cpython-subprocess. A full pass is ~1–2 h on a 10-core Mac and is not
   viable on 3 vCPU. The smoke tier is the PR gate; full tier is nightly/self-hosted.
6. **NOT a tolerance band on structural amplification counts.** A band is exactly
   where silent drift lives, and the project's determinism standard is absolute.
   Structural counts are exact integers or they are not gated at all (§6.4).
7. **NOT a hard amplification gate on day one.** See §6.7 — it cannot be, and
   saying otherwise would be the "counting work as done that was never
   live-verified" failure the strategy assessment warns about.

---

## 3. The CI rewrite

### 3.1 The spine: five ways this gate can report green having tested nothing

This must be settled **before** any hosted lane is declared gating, because the
project has been bitten repeatedly by exactly this
(`bsdvm` stage1 `report_only`; the probe gate SKIPping every lane and reporting
`ok` in 0.04 s from the wrong cwd; bhyve/NVMM live tests `eprintln!("skip")` and
returning). All five are verified in this session:

| # | Hole | Evidence | Fix |
|---|---|---|---|
| **H1** | **A missing oracle is NON-gating.** `Verdict::OracleFail` sets `gating: false`. On a Docker-less host a cache miss yields exactly this: the spawn fails → `SuiteResult::empty()` → `SuiteOutcome::Empty` → OracleFail. | **[V]** `crates/carrick-conformance/src/verdict.rs:152-160` | `--require-oracle` (implied on hosted lanes) makes it gating, **plus** a run-free `--check-oracle-coverage` that recomputes every selected suite's `oracle_key` and asserts it is in the committed cache. Catches it on `ubuntu-latest` in 10 s instead of silently on macOS in 10 min. |
| **H2** | **NEW rows are non-gating.** First observation with no baseline row → `(Verdict::New, false)`. | **[V]** `verdict.rs:223` (`base.is_none()` arm at `:221`) | 72 suites have no baseline row today. Make NEW gating on the ecosystem manifest, or force-triage before a bless. |
| **H3** | **DIFF rows are non-gating** once blessed — every divergence excused by a `known_gap` or a baseline pair lands here. | **[V]** `verdict.rs:219` | Same. |
| **H4** | **66 LTP suites carry a blanket `known_gaps = ["summary"]`** — on the only token an LTP suite emits, making them structurally unfailable regardless of what carrick does. | **[V]** `grep -c 'known_gaps = \["summary"\]' scripts/conformance/suites.toml` → **66** | Audit them (strategy assessment item 4). Out of scope here except: **never** let an ecosystem suite use a blanket gap. |
| **H5** | **A crash/timeout with no baseline entry downgrades to NEW.** `let gating = baseline_entry.is_some();` — so a suite that has never been seen can CARRICK_CRASH and not gate. | **[V]** `verdict.rs:171-176` | Acceptable for the legacy corpus; **not** for a hand-authored ecosystem test, where a missing baseline row means the author skipped a step. Per-manifest policy, not a global constant. |

**Design rule adopted throughout:** *a gate that has never been observed red gated
nothing.* Every new gate in this spec ships with a red-first proof — the habit
`9c421058` established ("verify what refresh-golden publishes instead of assuming
it"). And every `check-*` recipe **asserts a non-zero comparison count** and fails
if it compared nothing.

### 3.2 The job matrix

Legend: **H** = GitHub-hosted (free; repo is public — **[E]** `gh api
repos/carrick-sh/carrick` → `"visibility":"public"`, so no macOS 10× multiplier
and no minute budget to design around). **S** = self-hosted.

#### Hosted

| Job | Runner | Proves | Budget | Status |
|---|---|---|---|---|
| `gate` | `macos-15` (arm64) **H** | `just ci` **verbatim** — fmt · clippy · lint-domains · deny · check-matrix · check · doc · test · test-integration | ~8–12 min cold build, ~3–6 min warm; **[E]** cold `cargo build --release -p carrick-cli` = 4m18s on 10 cores ⇒ **[I]** ~10–14 min on 3 | **Exists, RED.** Rewrite to call `just ci` (today it omits `lint-domains` and `check-matrix` — **[V]** compare `justfile` `ci` recipe against `ci.yml`'s `check` job) |
| `native-acceptance` | `macos-15` **H** | **NEW: guest execution on a hosted runner.** Tier-1 cargo acceptance tests (§4.2) + the `carrick-cli` test targets no CI job runs today (C7) | ~3–6 min | **New.** Gating from the moment it is green |
| `native-ecosystem` | `macos-15` **H** | **NEW: real ecosystem workloads on the shipped default backend.** `carrick-conformance --lane macos-native-dsr` over the ecosystem manifest | ~5–15 min at smoke scope | **New. Report-only at first** — see §3.4 |
| `cross-check-linux` | `ubuntu-latest` **H** | aarch64-linux closure + no-HVF closure assert; native `carrick-host-linux` unit tests | ~3–5 min | Exists; extend with `check-freebsd-arm64` / `check-netbsd-arm64` (strategy assessment's parallel XS item — **[V]** neither exists: `rg 'aarch64-unknown-(freebsd\|netbsd)' justfile .github/` → zero hits) |
| `cross-check-freebsd` | `ubuntu-latest` **H** | `platform-freebsd` CLI+runtime closure | ~5–8 min (cached sysroot) | **Exists, RED** — `E0432` unresolved `bad64`, `dynasmrt`, `crate::runtime::maybe_dump_debug_state`, `ValidatedPreparedImage`. Invisible locally: `just ci` does **not** run `check-freebsd` |
| `cross-check-netbsd` | `ubuntu-latest` **H** | nvmm backend closure | ~2–4 min | Exists; extend past `-p carrick-vmm-nvmm` to the **native** closure — the just-landed NetBSD native lane has **zero** CI protection |
| `probe-build` | `ubuntu-24.04-arm` **H** | Builds the 432-probe aarch64 musl set; uploads as an artifact | **[E]** 12.2 s | **New.** Note: this needs **no Docker** — `scripts/build-probes.sh` shells `docker run rust:alpine`, but the same build runs in 12.2 s with rustup + `rust-lld`. Could equally run on the macOS job |
| `oracle-refresh` | `ubuntu-24.04-arm` **H** | Nightly. **Native arm64 Docker, no QEMU.** Runs the *ecosystem manifest only* with `--refresh-oracle`; opens a PR with the `oracle-cache.jsonl` delta | ~2–5 min | **New.** This removes the maintainer's Mac from the critical path for new tests — the thing that would otherwise make this loop unusable by anyone else |
| `oracle-refresh-amd64` | `ubuntu-latest` **H** | Same, `linux/amd64`. Directly addresses "x86 bless DEV-blocked (644 missing amd64 oracles)" | ~2–5 min | **New**, optional/later |
| `fleet-aggregate` | `ubuntu-latest` **H** | Downloads every lane's `results.jsonl`, renders the fleet + syscall-coverage matrices, enforces `--require-lane`. **`if: always()`** | seconds | **New** (§5) |
| `deny` | `ubuntu-latest` **H** | licenses · bans · sources | ~2 min | Exists (also inside `just ci`; keep the standalone job for fast signal) |

#### Self-hosted — and why each MUST stay

| Job | Runner | Why it cannot move |
|---|---|---|
| `hvf-conformance` | `[self-hosted, macos, arm64]` **S** | **[V/E]** HVF needs `com.apple.security.hypervisor`, and GitHub documents *"Nested-virtualization is not supported due to the limitation of Apple's Virtualization Framework"* on hosted macOS. Hosted arm64 macOS is M1; Apple's nested virt needs M3+. This is also the only macOS box with Docker, so it owns the live arm64 oracle, `just conformance-probes` (which drives `bollard` directly and self-skips without a daemon), and the **raw** amplification tier (`carrick trace` auto-sudos and needs `/dev/dtrace`). **Fix before enabling:** `ci.yml:288` runs `cargo test --workspace`, which violates `justfile`'s deliberate split (carrick-runtime tests fork from the harness and deadlock in parallel; the recipe runs them alone under `RUST_TEST_THREADS=1`). Point it at `just test` + `just test-integration`, plus an explicit `--ignored` step for the guest-booting tests. |
| `kvm-smoke` / `kvm-local` | `[self-hosted, linux, kvm]` **S** | `just kvm-smoke`'s fixture is **aarch64**, so it needs an aarch64 KVM host and does **not** move. The amd64 `--lane kvm-local` **might** move to hosted `ubuntu-latest` pending open question (5). |
| bhyve / NVMM / BSD lanes | fleet **S** | **[V]** No GitHub-hosted FreeBSD or NetBSD runner exists. A cross-platform-action VM is x86-emulated and unusable as a guest lane. Permanently self-hosted. |

### 3.3 How the Docker oracle fits without making the gate non-deterministic

**[V] The suite gate is already Docker-free when the cache is warm.**
`crates/carrick-conformance/src/oracle.rs:2-6`: *"we skip docker for any suite
whose key is already cached and diff carrick against the cached oracle — so a
routine run executes ONLY carrick."* The committed cache is 6,312 records
(**[V]** `wc -l`), and **[E]** an independent recomputation of `oracle_key`
matched **2127/2127** arm64 suites, MISS 0. **[E]** A live run confirmed it:
`--lane macos-native-dsr --suite go-errors --suite go-sync` printed
`phase 2/3: 0 docker run(s), 2 cached oracle(s)` with both MATCH.

The determinism rules that follow:

- **CI never writes an oracle.** Only the nightly `oracle-refresh` job does, and
  it does so by **opening a PR**, so an oracle change is a reviewed commit.
- **A cache miss in a gating job is a FAILURE, not a Docker fallback** (H1).
  Hosted macOS has no Docker; silently classifying a miss as OracleFail/non-gating
  is the flagship silent-green hole.
- **Content-addressing is free and must be preserved.** `OracleKey` is an explicit
  allowlist struct — **[V]** `oracle.rs:29-44`: `docker_platform, image, cmd,
  docker_flags, entrypoint, bind_mounts, env, workdir, verdict` — pinned by a
  golden test (`oracle.rs:387 golden_oracle_key_pins_the_determinant_schema`).
  Because the test source lives *inside* `cmd` (§4.1), editing a test changes the
  key, misses the cache, and forces a re-run. There is no hash field to maintain
  and no way to diff against a stale oracle.
- **Adding `Suite` metadata is free.** Because `OracleKey` is an allowlist and not
  a derive over `Suite`, new fields (`syscalls`, `amplify`) **do not invalidate any
  of the 6,312 committed records.** AGENTS.md's warning about a determinant-field
  change forcing a full fresh Docker pass does not fire. Add a golden test
  asserting the key did not move.
- **Digest-pin every new base image.** The key tracks the *declaration*, not the
  live image, so a moving `:1.24` tag would silently keep a stale oracle. Legacy
  suites cannot be pinned cheaply; new ones can.
- **`bind_mounts` is in the key and carries an absolute host path**
  (**[V]** `oracle.rs:36`) — so a mount-based test delivery produces a per-machine
  key and a permanently cold cache. This is why source-in-`cmd` beats a bind mount.

### 3.4 Cost, queue time, and why `native-ecosystem` starts report-only

**Cost: effectively zero.** **[E]** The repo is public, so hosted macOS-arm64 and
Linux-arm64 minutes are free and unmetered. The honest constraints are wall-clock,
queue depth, and the 14 GB disk (C9) — not billing.

**Queue time** is the real tax: `macos-15` arm64 runners have historically had the
longest queues of any hosted class. Mitigations: `concurrency: cancel-in-progress`
(already present), keep `native-ecosystem` off the PR path initially, and put the
full tier on `schedule` only.

**Why `native-ecosystem` cannot be gating on day one — the decisive number.**
**[V]** The strategy assessment records that the last measured run of the native
backend against the project's own 23-case smoke tier
(`target/conformance/native-default-goal-smoke-20260713.jsonl`, 2026-07-13) was
**15 match / 4 regression / 3 timeout / 1 carrick_crash, with all eight
non-matches `gating: true`** — `ltp-eventfd01`, `go-build`, `go-runtime`,
`go-sync`, `node-app-smoke`, `node-v8-smoke`, `cpython-subprocess`,
`cpython-threading`. **The ecosystem workloads this program wants to gate on are
precisely the ones that are red on the lane it wants to gate them on.** Plus
`scripts/conformance/baseline.native-dsr.jsonl` is **1 line** (**[V]**) — there is
nothing to regress against.

So the sequence is forced, and it is the strategy assessment's item 1 → 4 → 5:
**measure first (Phase 1), repair gate semantics (Phase 3), drive the list to
zero, then bless and turn the gate hard.** Declaring the job gating before that
would either block every PR or — worse — be quietly configured non-gating and
join the list of gates that report green having tested nothing.

---

## 4. The ecosystem-test format

### 4.1 Two tiers, with a hard boundary

Three test classes exist today and must not be conflated; the third is the missing
one.

| class | artifact | oracle | granularity |
|---|---|---|---|
| **probe** (432 in `conformance-probes/src/bin`) | freestanding aarch64-musl ELF emitting `key=value` | Docker byte-diff via `bollard`, or committed `probe-oracle/<lane>/<name>` | line-exact |
| **upstream suite** (2,127, generated) | someone else's suite in a private image | `docker run`, cached | per-test id |
| **ecosystem test** (proposed, **0 today**) | **carrick-authored source in a real runtime**, exercising one syscall *through the runtime's own abstraction* | the same cached-oracle machinery | per-assertion |

The bugs that actually bite are runtime-mediated: `cpython-threading
test_2_join_in_forked_process`, libuv `worker_threads` hitting the DSR `LDP` gap
(C4), `go build` dying at `ulimit -n 2048` (C1). **No probe would have caught any
of them.** That is the gap this class fills.

| | **Tier 1 — acceptance** | **Tier 2 — ecosystem** |
|---|---|---|
| Mechanism | `cargo test -p carrick-runtime --test native_<host>_<isa>` | `carrick-conformance --lane macos-native-dsr` |
| Guest | committed/built static Linux ELF, ≤ a few hundred KB | real OCI image on a **public, digest-pinned** base |
| Runs in | the test process (guest = its fork child) | a spawned `carrick` binary |
| Oracle | **none** — asserts carrick's own contract | Docker, via the committed cache |
| Hosted CI | **yes, today**, no Docker, no hypervisor, no images, no network | yes, once C5's `if` is fixed |
| Carries the ratchet | **yes — gated** | recorded, never gated |

**Tier 1 is the missing Darwin sibling.** **[V]**
`crates/carrick-runtime/tests/` contains `native_freebsd_x86.rs` and
`native_netbsd_x86.rs` but **no `native_darwin_aarch64.rs`**, and
`crates/carrick-native-darwin/tests` is empty. *The mature lane has less
end-to-end coverage than the two bring-up lanes.* That file is the cheapest,
most obvious deliverable in the whole program.

The one new public surface it needs: a Darwin arm of `run_elf_native_dispatch`.
**[V]** `crates/carrick-runtime/src/lib.rs:966` cfg's the existing one to
freebsd/netbsd + x86_64. Darwin's reachable equivalent today is
`runtime::run_static_elf_with_backend_args_and_dispatcher_debug`, which routes
`ExecutionBackend::Native` → `crate::native::run_static_native`
(`crates/carrick-runtime/src/native/mod.rs:208-262`, `pub`). One forwarding
function, same three-function shape as the FreeBSD arm.

### 4.2 Tier-2 delivery: source-in-`cmd` on a public image

```toml
# scripts/conformance/suites.ecosystem.toml  (NEW, hand-owned-but-tool-written)
[[suite]]
name       = "eco-cpython-close-range"
ecosystem  = "cpython"
image      = "docker.io/library/python:3.12-slim@sha256:<digest>"   # PUBLIC + digest-pinned
cmd        = ["/bin/sh","-c","echo <base64 of ecosystem-tests/cpython/close_range.py> | base64 -d > /tmp/t.py && python3 /tmp/t.py"]
verdict    = "kv"                       # NEW parser, see §4.3
tier       = "smoke"
timeout_s  = 120
carrick_flags = ["--raw","--fs","host"]
syscalls   = ["close_range","openat","close"]                 # NEW, non-determinant
amplify    = [{ syscall = "openat", max_host_ops_per_call = 6 }]  # NEW, non-determinant
```

Consequences, each checked against the code:

- **No registry, no Docker on the consuming side.** **[E]** carrick pulls with its
  own OCI client: `carrick pull docker.io/library/alpine:3.20` succeeded from an
  entitlement-free binary with an empty store in 1.06 s.
- **Content-addressed for free** (§3.3).
- **The reviewable artifact is `ecosystem-tests/<lang>/<name>.<ext>`**; the base64
  in the manifest is generated. TOML `'''` literals (as `go-build` uses) read
  better but break on a source containing `'''` or a backslash sequence — base64
  is the right engineering choice for a *generated* file.
- **Do NOT append to `suites.toml`.** It is generated by `--generate-suites`
  (which shells `docker` to enumerate modules), 1,492 of its 2,127 entries are
  LTP, and every regeneration would churn hand-written entries.
  `Manifest::validate` already enforces duplicate-name, `--fs host` pinning, and
  the `n=0` bare-image trap across the merged set.

### 4.3 `VerdictKind::Kv` — the missing granularity

**[V]** Both plausible reuse targets are coarse by construction:
`ShellParser` (`parsers/shell.rs:16-29`) and `TapParser` (`parsers/tap.rs:17-40`)
emit a **single synthetic** `"suite"` id with `totals.n == 0`. A 30-assertion
ecosystem test that regresses one assertion would classify as one `Fail` with no
diff detail, and `known_gaps` (which matches on ids) would have nothing to excuse.

`KvParser` is ~80 LoC plus fixture tests, mirroring the five existing parsers:
strip carrick banners via the existing `parsers::strip_carrick_banners`, then emit
one id per `key=value` line, **folding the value into the id**
(`ids["close_range_closed_all=true"]`) so a changed value surfaces through the
differ's existing per-id set-diff as `Absent`-vs-`Ok` — no new diff semantics.
This reuses the probe corpus's proven vocabulary
(`conformance-probes/src/lib.rs:11-14`: *"one `key=value` line per observation …
NEVER timing data, never PIDs, never addresses"*).

### 4.4 How a test declares which syscalls it exercises

This is what makes "validate a syscall across the fleet" possible, and it needs
**two** mechanisms, because either alone is wrong:

- **MEASURED (authoritative).** The per-`CanonicalNr` invocation histogram from
  §6.2 rides on the result record. It is a by-product of running the thing, so it
  **cannot go stale**. This is what answers "which suites issue `openat`?"
- **DECLARED (intent).** A `syscalls = [...]` field on the suite / a
  `//! syscalls: close_range, openat` header in a probe, scaffolded by
  `scripts/new-probe.sh`. Needed *in addition* because a test's **intent** differs
  from its **incidental** syscalls.

**[E] Why declaration alone fails, with the counter-check that proves it:** a
name-grep over all 432 probe sources shows `mkdir` matching **54** files —
overwhelmingly incidental setup, not `mkdirat` ABI coverage — while `inotify`,
`unshare`, `sethostname`, `close_range` and `copy_file_range` genuinely match 0.
Grep cannot be the mechanism. **Why measurement alone fails:** it would credit
that same incidental `mkdir` as coverage. Render them as **separate columns**.

**[E]** 37 of 225 BringUp syscall names appear in **zero** probe source, including
the clusters: `close_range`, `copy_file_range`, the whole `inotify` family,
`unshare`, `sethostname`/`setdomainname`, `membarrier`, `rseq`,
`process_vm_readv`/`writev`, `recvmmsg`/`sendmmsg`, `mq_notify`. That list is the
initial work queue for ecosystem tests.

### 4.5 The drift gate that makes the syscall axis honest

**[V] The `SupportLevel` table that both the docs and `carrick syscalls` call
"the authority" has drifted from the dispatcher by 34 syscalls** — routed to real
handlers but still reported `deferred`/`unimplemented`. Spot-verified as real
handlers, not ENOSYS stubs: `memfd_create` (279) at `dispatch/fs.rs:10884`,
`cachestat` (451) at `fs.rs:9298`, `chroot` (51) at `fs.rs:5105`, `futex_waitv`
(449) at `dispatch/proc.rs:2252`, `rt_tgsigqueueinfo` (240) at
`dispatch/signal.rs:2091`, `timer_create` (107) at `dispatch/time.rs:454`,
`epoll_pwait2` (441) at `dispatch/net.rs:4044`. Live:
`carrick syscalls --number 279` → `{"support":"deferred","handler":"unimplemented"}`.

The nearest existing test
(`crates/carrick-runtime/tests/integration/syscall_table.rs:257-269`) only asserts
`BringUp ⇒ the static handler_for_aarch64 range-match != Unimplemented` — it never
consults `resolve_handler`/`syscall_table!`. And
`docs/syscalls-emulation-map.md:308-315` **documents the drift as a permanent
TODO** rather than fixing it.

**One `#[test]` closes it permanently:**

```rust
// crates/carrick-runtime/tests/integration/syscall_table.rs
#[test] fn support_level_matches_the_dispatcher() {
    // BringUp  ⟺  resolve_handler(nr).is_some()
    // Deferred ⇒  !routed
}
```

This is the single highest-leverage missing gate found anywhere in this program,
it is ~20 lines, and it makes the support level self-maintaining.

### 4.6 Worked example — a contributor improves `close_range` fidelity

Chosen because it is genuinely uncovered (**[E]** zero probe files mention it), it
is structural (⇒ gateable for amplification), and CPython's `subprocess` really
calls it for fd cleanup — so it is a true ecosystem test, not a synthetic one.

**Files touched**

```
 crates/carrick-abi/src/lib.rs                      # CLOSE_RANGE_* flags via bitflags!, NOT hand-numbered
 crates/carrick-abi/src/syscall.rs                  # row → SupportLevel::BringUp (table stays strictly sorted)
 crates/carrick-runtime/src/dispatch/fs.rs          # handler + its ONE syscall_table! arm
 fixtures/linux-aarch64-hello/src/close_range.rs    # ~30-line no_std guest  (tier 1)
 scripts/build-linux-fixtures.sh                    # one build_fixture line
 crates/carrick-runtime/tests/common/cases.rs       # one Case { .. } literal  (tier 1)
 conformance-probes/src/bin/closerangeflags.rs      # line-exact probe        (truth)
 ecosystem-tests/cpython/close_range.py             # the ecosystem test      (tier 2)
 scripts/conformance/suites.ecosystem.toml          # GENERATED — do not hand-edit
```

**Commands run**

```bash
# 1. red-first, tier 1 — seconds, laptop, no Docker, no signing, no images
./scripts/build-linux-fixtures.sh                          # rustc + rust-lld, ~2s
cargo test -p carrick-runtime --test native_darwin_aarch64 -- close_range   # RED

# 2. implement the handler, then:
cargo test -p carrick-runtime --test native_darwin_aarch64 -- close_range   # GREEN

# 3. scaffold + generate
just new-ecosystem-test cpython close-range     # writes the .py + header block
just gen-ecosystem-suites                       # rewrites suites.ecosystem.toml

# 4. get the LINUX truth. Either on the Docker box, OR let the nightly
#    hosted arm64 oracle-refresh job produce it and open a PR.
just conformance full --manifest scripts/conformance/suites.ecosystem.toml \
     --suite eco-cpython-close-range --refresh-oracle
#    → commits ONE oracle-cache.jsonl line = blessed Linux behaviour

# 5. carrick side. A DIFF here is YOUR BUG — and it is a bug about Linux
#    behaviour, not about your belief.
just conformance-native smoke --suite eco-cpython-close-range

# 6. fleet + ratchet
just fleet --syscall close_range          # every lane THIS host has (§5)
just amplify-bless --suite eco-cpython-close-range --reason "first record"

# 7. the local gate — now also runs the new run-free checks
just ci
```

**One commit contains:** the syscall, the tier-1 fixture + case, the probe + its
oracle, the ecosystem test, its oracle line, its amplification record, and the
regenerated manifest. Steps 3, 6, 7 are deterministic and need neither Docker nor
a guest.

### 4.7 Fixtures: reproducible without bloating the repo

**[V]** `scripts/build-linux-fixtures.sh` builds ~60 static aarch64-musl Linux
ELFs using **only** `rustc --target aarch64-unknown-linux-musl` + the bundled
`rust-lld` — it explicitly checks `rustup target list --installed` and the
`rust-lld` path. **No Docker, no network.** **[E]** The sibling 432-probe musl set
cross-builds on macOS in **12.2 s**; ~60 fixtures is ~2 s.

Policy:
- **aarch64 fixtures stay gitignored and built** (`.gitignore: /fixtures/*/target/`).
  The lane always has a rustc that can build them.
- **x86 fixtures stay committed** (73 tiny files under
  `crates/carrick-dsr-x86/tests/fixtures/`, with a committed regeneration recipe in
  its `README.md`). The BSD lanes may not have a cross-toolchain.
- **Never commit a Go or std-Rust binary.** **[V]** `hello-std-x86_64-linux` is
  already 4.65 MB; a Go static binary is larger.
- **Ecosystem-test sources are text** (`ecosystem-tests/**`), base64'd into the
  generated manifest. Zero binary weight.

**[E] A warning that must be respected:** `run-elf` on the checked-in freestanding
fixtures produces **empty stdout on native** and correct bytes on VMM (same exit
codes, which do agree and are non-trivial — sp-fault → 139 on both). Native stdout
*is* genuinely captured (`native_darwin.rs:1551-1598` pipes the fork child's fd1),
so `""` is real. **Those specific fixtures are not a valid native smoke gate
as-is** and the divergence needs root-causing before they are gated — most likely
guest-VA→host-VA translation of the pointer passed to `write(2)`.

---

## 5. The fleet validation loop

### 5.1 The gap is a join key, not an orchestrator

**[V]** Every lane already emits the same record type — `SuiteReport`
(`crates/carrick-conformance/src/verdict.rs:58`) — into `results.jsonl`, and that
record has **no lane field, no host/env field, and no syscall field**. It cannot
be joined with itself. That is the entire gap. `docs/support-matrix.md` contains
zero occurrences of the word "lane."

Extend the existing record; do not invent a new one. Every field is
`#[serde(default)]`, so the 2,064 committed baseline rows stay loadable.

```rust
pub struct SuiteReport {
    /* ...existing fields unchanged... */
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvKey>,                      // WHERE this row came from — the join key
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exercised: BTreeMap<u32, u64>,            // canonical nr → invocations (summed over the fork TREE)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hostops: BTreeMap<u32, HostOps>,          // the ratchet payload (§6)
}

/// Everything that legitimately moves a count or a verdict. Modeled on
/// `OracleKey` (oracle.rs:29-65), whose precedent is explicit: adding a
/// determinant field invalidates every committed key at once and forces a
/// CONSCIOUS re-bless. That is the desired property, not a side effect.
pub struct EnvKey {
    pub lane: String, pub host_os: String, pub host_isa: String,
    pub exec_backend: String, pub page_profile: String,
    pub fs_backend: String, pub fs_flags: String,      // CARRICK_FS_STATCACHE / _OVERLAY / FAST_FS
    pub identity_shim: bool,                            // false under seccomp — §6.5
    pub instrumented_domains: u8,                       // bitmask: 0 means "not routed", NOT "no work"
    pub commit: String, pub runner: String,             // "github-hosted:macos-15" | "self-hosted:mac16,12" | "willow:vm200"
}
```

The aggregator (`crates/carrick-conformance/src/fleet.rs`, ~600 lines) is a **pure
function** over a directory of `results.jsonl` files of any provenance —
downloaded CI artifacts, local runs, fleet scp. No execution, no network, no SSH,
no Docker. Deterministic order, no timestamps, so `git diff` on the render **is**
the review — exactly the contract `matrix.rs:1-3` already establishes.

### 5.2 One command, honest skipping

```
just fleet [--syscall close_range] [--suite eco-cpython-close-range]
```

runs **only the lanes this host actually has**, using detection predicates that
already exist:

| lane | existing predicate | source |
|---|---|---|
| `hvf` | codesign entitlement contains `com.apple.security.hypervisor` | `main.rs:1588` |
| `macos-native-dsr` | macOS/aarch64 **and** 16 KiB pages | `page_profile.rs:124-140`, `:143-170` |
| `kvm-local` | `/dev/kvm` | `preflight_kvm_local` |
| `bhyve-local` | `/dev/vmm` / `/dev/vmmctl` | `preflight_bhyve_local` |
| `nvmm-local` | `/dev/nvmm` | `preflight_nvmm_local` |

On a fresh Mac that means `{hvf, macos-native-dsr}` run and the other four render
`unproven` — which is the truth.

**Never silently green — three mechanisms, because the project has been bitten by
each failure shape:**

1. **`unproven` is a distinct render state**, not a blank and not a pass. Cell
   vocabulary is `MATCH-covered` / `DIFF-covered` / `unexercised` / `unproven
   (lane absent)`. Only the first two are evidence.
2. **`--require-lane <name>`** — a missing lane is a non-zero exit. This is what
   stops the current shape where `hvf-conformance` and `kvm-smoke` both report
   `skipped` and the run still concludes green.
3. **`if: always()` on `fleet-aggregate`** — a lane that *failed* must still
   contribute its rows, or the matrix silently narrows to the green lanes.
4. **Every `check-*` recipe asserts a non-zero comparison count** and fails if it
   compared nothing (the probe-gate-from-the-wrong-cwd shape).

### 5.3 What the output looks like

```
docs/fleet-matrix.md          suite × lane → verdict, `unproven` for absent lanes
docs/syscall-coverage.md      canonical nr × lane → {MATCH-covered n, DIFF-covered n,
                              unexercised, unproven}, cross-joined with the ROUTED set
                              from carrick-abi so emulated-but-never-exercised is visible
docs/perf-matrix.md           workload × nr → essential_host_ops / invocations, Δ vs baseline
```

Keep `docs/support-matrix.md` HVF-authoritative so `check-matrix` keeps passing —
but **stamp it with the lane, backend, commit and date it was rendered from**
(today it names none, and it is a five-week-old VMM render presented as
"auto-generated carrick-vs-Docker").

**Honest first output.** **[V]** 4 of 6 lane baselines are empty
(`native-dsr` 1 line, `kvm-arm64` 0, `nvmm` 0; `kvm`/`bhyve` 9 each;
`baseline.jsonl` 2,064). **A fleet matrix rendered today would be a wall of
blanks** — which is the correct, useful output, and it is the argument for making
"measure and then bless the native lane" the first deliverable rather than a later
one.

**The honest limit, which must be printed in the render header:** `exercised[nr] >
0 && verdict == MATCH` proves the syscall was **touched and behaved compatibly for
that usage on that lane**. It is **not** a fidelity proof. If this render is ever
cited as a support claim it becomes a second drifting `SupportLevel` table. The
cell vocabulary deliberately never says "supported."

---

## 6. The syscall-amplification ratchet

### 6.1 Status: designed in full, in this repo, and never built

**[V]** `docs/superpowers/specs/2026-07-03-conformance-probe-perf-coverage-design.md`
plus its plan specify the `hostcall` accounting seam, per-`CanonicalNr`
attribution at the dispatch chokepoint, an env-gated JSON report
(`CARRICK_PERF_REPORT`), a committed `scripts/conformance/perf-baseline.jsonl`, and
a `just check-perf` gate mirroring `just check-matrix`. A repo-wide grep for
`CARRICK_PERF_REPORT`, `check-perf`, `perf-baseline` over `*.rs`/`justfile`/`*.yml`
returns **nothing outside `docs/`**; the plan is **0 of 37 steps checked**.

**So this is execution of an existing reviewed plan, not a new design** — with
four corrections (§6.3, §6.5, §6.6) the original does not carry.

### 6.2 What is measured, and in what unit

**Per-workload, per-guest-syscall-kind ratio. Never one aggregate.**

The aggregate is actively misleading: it moves whenever the workload's syscall
*mix* moves, with no change in carrick. Worse, **[V]** identity syscalls
(`getpid/getuid/geteuid/getgid/getegid` + `gettid`,
`crates/carrick-mem/src/memory.rs:244-250`) are answered in the EL1 shim with zero
VM exits, or stamped inline by the x86 DSR gateway
(`carrick-dsr-x86/src/gateway.rs:813`), and **never reach the dispatcher** — so
they are silently absent from the denominator, and a seccomp policy
(`crates/carrick-runtime/src/seccomp.rs:305,311` clears
`identity_fast_path_allowed`) switches them back on. That would *lower* every
aggregate ratio with **zero change in host work**: a phantom improvement.

The known pathology is also per-kind: **[V]**
`docs/fs-host-capstd-amplification.md` reconciles 999,646 host opens ÷ (6 walks ×
3,335 guest opens) ≈ 45 raw `openat` per cap-std walk, i.e. ~291 host opens per
guest open under `--fs host`. And the UPDATE-3 campaign tracked
host-syscalls-per-guest-**stat** (15 → 11 → 1). Both are per-kind numbers.

**Gated quantity:** `essential_host_ops / invocations` per `(workload, lane,
CanonicalNr, domain)`, stored as an **exact rational** (numerator + denominator;
never compare floats). A test doing 10× the opens has 10× both, so the ratio is
flat — that is the whole reason the ratio and not the total is gated.

**A note that must be printed everywhere this number appears:** the `--fs host`
cap-std path is **the only fs backend in a default build** — **[V]**
`crates/carrick-spec/src/lib.rs:224-233`, where `Memory` is behind a default-off
`fs-memory` feature and `Host` is documented "The only backend in a default
build." The 291× figure is macOS-specific (no `openat2`/`RESOLVE_BENEATH`) but it
is **not** a niche-mode number. Every default macOS guest pays it.

### 6.3 Where it is collected

**On the native lane, because attribution there is structurally exact.** **[V]**
With no hypervisor, carrick's own process makes the host syscalls, so a
thread-local "currently dispatching nr" guard attributes them precisely —
`dispatch_native_syscall_inner` → `dispatcher.dispatch_threaded(...)` at
`crates/carrick-runtime/src/native_darwin.rs:4228,4238`. No VM-exit boundary, no
DTrace, no sudo, no `/dev/dtrace` ⇒ **it runs on a hosted runner**.

- **Denominator:** an RAII guard at the single dispatch chokepoint
  (`crates/carrick-runtime/src/dispatch/mod.rs:3542`), bumping `invocations[nr]`.
  Place it **after** the seccomp/policy prechecks and **before**
  `dispatch_threaded_shared`, because the shared path returns early and the
  existing `reporter.record(SyscallEntry)` therefore only sees the ENOSYS
  fallthrough.
- **Numerator:** a new `hostcall::{fs,net,mem,proc}` seam. Instrument
  `fs_backend.rs` **first** (the marquee amplifier). ~4,001 `libc::` references
  exist in `carrick-runtime`, so this is necessarily incremental — hence
  `instrumented_domains` (§6.6).

**CORRECTION 1 — do not use process-wide atomics on the hot path.** The original
design specifies them. With 8 guest threads all issuing `openat`, every record is
a contended RMW on one cacheline, against a ~1.8 µs trap floor and an fs fast path
already driven to ~3.5 µs per guest stat. Use **per-thread arrays merged at
process exit**. **[V]** `carrick-observability/src/compat.rs:12-23` records that
an earlier hot-path shape (per-event `Vec` + `String` allocation) was removed for
exactly this reason — do **not** extend `CompatReporter`'s HashMaps. And per the
project's own memory (*"lock-free can be net-negative — untraced back-to-back is
the only authority"*), the instrumentation must be measured back-to-back against
an uninstrumented build **before it lands**, and reverted if it does not pay.

**CORRECTION 2 — prerequisite: both native lanes currently throw the report
away.** **[V]** `crates/carrick-runtime/src/native_darwin.rs:1613` and
`native_freebsd.rs:8565` both construct `RunResult { …, report:
CompatReport::default(), … }` while a live `CompatReporter` is threaded right
through the dispatch path. **The data is collected and discarded on the lane the
maintainer wants to make primary.** Two lines; a hard prerequisite for everything
here and for §5's `exercised`.

### 6.4 Determinism — the crux, handled by self-policing, not assertion

Three classes, from the code:

| class | examples | treatment |
|---|---|---|
| **STRUCTURAL** — pure functions of the guest request and the fs backend's algorithm | `openat`, `newfstatat`, `statx`, `readlinkat`, `getdents64`, `close`, `mmap`, `munmap`, `mprotect`, `unlinkat`, `renameat`, `*xattr` | **GATED, exact equality.** No band. |
| **TIMING-COUPLED** — both numerator *and* denominator wobble | `futex`, `epoll_pwait`, `ppoll`, `pselect6`, blocking `read`/`write`, `sched_yield` | **Recorded and rendered; NEVER gated.** |
| **STRUCTURALLY INVISIBLE** | identity syscalls (§6.2) | Excluded from the denominator by construction; `identity_shim` pinned in `EnvKey`. |

**[V] Why the timing-coupled class is irreducibly noisy:**
`native_darwin.rs:4217` opens a `loop {` around `dispatch_threaded`, and the
`WaitOnFds`/`WaitOnPollFds`/`WaitOnFdsSelect` arms `continue` on
`NativeWaitResult::Ready` and again on EINTR-plus-quiesce-nudge
(`native_darwin.rs:4270-4290`); `crates/carrick-host/src/ulock.rs:722,735` has
explicit wake-retry loops.

**CORRECTION 3 — split `essential` from `retries` at the source, so blocking
syscalls become partially gateable instead of merely excluded.** The re-entry is
already **explicit** in the code: the loop *knows* it is on iteration ≥ 2. So the
RAII guard carries a `pass: u32`; `essential` is bumped on pass 0 and `retries`
thereafter. Then even a `futex`-heavy workload has a gateable `essential/invocations`
while its `retries` is trend-only. **Caveat that must be respected:** every
`continue` in that loop must bump `pass`, or retry work is silently reclassified
as essential and the gate flakes.

**Self-policing rather than a hand-maintained allowlist.** The harness runs the
amplify-flagged cases **N=3** on the gating lane and **refuses to gate any
`(case, nr, domain)` whose `max != min`**; unstable ones are recorded with
`"gated": false` and rendered as trend. This is evidence-based, self-maintaining,
costs 3× wall-clock on an opt-in subset only, and means a contributor never has to
know which class their syscall is in.

**NEEDS-MEASUREMENT before the first bless** (do not assume): on a quiet box, run
each candidate gated case **20×** back-to-back and disqualify any `(case, nr,
domain)` with `max − min ≠ 0`. Predicted stable: `openat`/`fstatat`/`getxattr`/
`close`. Predicted possibly unstable: `fcntl(F_GETPATH)` if the stat cache warms
differently. Grep the logs with `-a` — AGENTS.md warns gate logs contain binary
bytes and matches vanish without it.

**A determinism hazard the original design misses: the stat cache is default-ON.**
`CARRICK_FS_STATCACHE` ships enabled and drove stats to one host syscall per guest
stat. Host-op counts are therefore a function of cache warmth — deterministic
within one cold process, deterministic across runs **only if scratch/rootfs state
is identical**. Hence `EnvKey.fs_flags`, and hence: **each perf-measured workload
runs from a fresh scratch** (which the job needs anyway, because scratch leaks
1.4 GB on SIGKILLed runs despite `--rm`, C9).

**Wall-clock never gates.** Counts only. This is also what makes the ratchet safe
on a noisy 3-vCPU shared runner: a structural count is indifferent to co-tenancy,
whereas any timing gate there is pure flake.

### 6.5 Storage and review

A **separate file**, deliberately: `scripts/conformance/amplification.jsonl`
(shared) + `amplification.<lane>.jsonl` overlays, reusing the existing
`BlessTarget::{SharedBaseline, LaneOverlay}` split (`main.rs:810-846`) verbatim so
a bring-up lane can never overwrite mature-lane ground truth.

Why not inside `baseline.jsonl`: **[V]** `--bless` requires a **full-tier,
unfiltered** run (`main.rs`), so a per-syscall change could never bless just its
own suite. Also **[V]** `SuiteReport` already carries `perf: Option<PerfSummary>`
that is *reported but never gated* (`main.rs:1330-1387` warns at 10×, "critical"
at 100×, no exit-code effect), and the committed baseline contains **zero**
`"perf"` keys — so the next `--bless` will inject 2,064 wall-clock numbers into it.
Do not compound that.

```json
{"lane":"macos-native-dsr","suite":"eco-cpython-close-range","syscall":"openat",
 "invocations":41,"essential_host_ops":246,"ratio":"246/41","gated":true,
 "determinants":{"exec_backend":"native","fs_backend":"host","page_profile":"native16k",
                 "seccomp":"docker-default","identity_shim":true,
                 "instrumented_domains":["fs"]},
 "reason":"first record — cap-std per-component walk, 6 logical opens per guest openat"}
```

**CORRECTION 4 — `determinants` is not decoration.** It mirrors the `OracleKey`
discipline the project already knows how to apply. The comparator **hard-errors**
(never warns) on a mismatched `instrumented_domains` mask, because a partially
routed seam makes an uninstrumented site read `0` — indistinguishable from "did no
work," i.e. from an improvement. **`None` and `0` must be distinct types
end-to-end; a missing report is a hard error, never an empty map.**

**CORRECTION 5 — emission must be per-pid.** Counters are process-global and
carrick forks **real host processes** for `clone(2)`, so the original single
`CARRICK_PERF_REPORT=<path>` is last-writer-wins and would silently under-report
**every fan-out workload** — precisely the go/cpython/node set this program
prioritises. Use `CARRICK_PERF_REPORT_DIR=<dir>`, each guest process writing
`<dir>/perf.<pid>.json` at exit, and the harness **sums the tree**. (For tier-1
cargo tests there is a cheaper option: the test process is the arena owner and the
guest's parent, so counters can live in the existing fork-coherent
`carrick_kernel::arena::KernelArena` — "one file-backed `MAP_SHARED` region per
run, mapped before the first guest fork and inherited by every descendant" — and
be read directly after `waitpid`, with no report files at all.)

### 6.6 The explicit-acknowledgement mechanism

- **`just check-amplification`** (in `just ci`, run-free — compares the last run's
  `target/conformance/amplification.observed.jsonl` if present, else validates
  schema/determinant coherence): **observed > recorded → HARD FAIL**, printing the
  per-syscall diff.
- **Improvement (observed < recorded) also fails**, with *"improvement detected;
  run `just amplify-bless`"*. A stale-low baseline is a ratchet that has stopped
  ratcheting.
- **CI never writes.** A scheduled job may *propose* tightened numbers as a PR.
- **`just amplify-bless` REFUSES to write a record whose number increased unless
  `--reason "<text>"` is supplied**, and `reason` is a required schema field for
  any increased record. Symmetrically, `check` fails if a `reason` is attached to a
  record that did **not** increase — so reasons cannot be pre-planted.
- **The acknowledgement is the commit, not a flag.** Re-blessing rewrites a
  committed JSONL file and re-renders `docs/perf-matrix.md`. A regression is
  therefore a reviewable `git diff` whose justification lives in the commit body,
  under the project's existing **Why / What / Verified** norm. No separate
  mechanism is needed or wanted. This reuses `bless_blocks` (which already refuses
  to bless TIMEOUT/CARRICK_CRASH) verbatim in spirit.

### 6.7 Hard gate on day one? No — and exactly what would make it hard

**It must start report-only.** Four independent reasons, each verified:

1. **The seam does not exist** (0/37 steps). There is no number yet.
2. **The workloads it measures are red.** The native smoke tier was 8/23 gating
   twelve days ago (§3.4). You cannot ratchet a workload that does not complete.
3. **Instrumentation coverage will be partial for a while** (4,001 `libc::`
   references), so most domains read 0 and comparisons are refused by design.
4. **The determinism evidence has not been collected** — the 20× stability run
   (§6.4) is the gating input, and it has not been done.

**Promotion criteria — each objective, each checkable:**

- [ ] `perf.rs` + the `fs` domain of `hostcall` are landed, and the back-to-back
      overhead measurement shows no regression against an uninstrumented build.
- [ ] Both native lanes' `RunResult` carry a real report (§6.3 correction 2).
- [ ] The 20× stability run has produced an evidence-based gated set, and every
      member has `max == min` across 20 runs.
- [ ] ≥5 ecosystem tests exist whose gated syscalls are all STRUCTURAL, and they
      pass on the native lane.
- [ ] The ratchet has been **observed RED** by deliberately regressing a host-op
      count (red-first proof — a gate never seen red gated nothing).
- [ ] `check-amplification` asserts a non-zero comparison count.

When all six hold, flip `check-amplification` to hard **for the STRUCTURAL class
only**. Timing-coupled kinds stay trend-forever.

### 6.8 The honest limitation — state it loudly and in the render header

**The logical `hostcall` seam would have reported ~6, not 291.** **[V]** The
design doc's own Non-goals: *"We do not count the raw `libc` syscalls a dependency
issues internally — e.g. cap-std's per-component path walk that turns one carrick
open into ~45 raw `openat`s."*

So this is a **regression detector, not a pathology detector.** Two tiers:

| tier | counts | runs | gating |
|---|---|---|---|
| **logical** (`hostcall`) | carrick's own host operations | anywhere, incl. hosted macOS | **YES** (after §6.7) |
| **raw** (DTrace) | cap-std's internal multiplication | **self-hosted macOS only** — `scripts/dtrace/syscall-amplification.d` already computes HOST_TOTAL/GUEST_TOTAL, but `carrick trace` auto-sudos and needs `/dev/dtrace` | report-only, nightly |

**And the root-cause note, per "no pragmatic shortcuts":** the correct fix for the
raw tier is not a second permanent gate but
`docs/cap-std-demotion-plan.md` (stages 1–6, all unstarted). **Once carrick issues
the `openat`s itself, the logical count *becomes* the raw count and the two tiers
collapse into one.** The ratchet should be framed as instrumentation *for* that
plan — the thing that proves it landed and stays landed. Shipping the ratchet
without the demotion is defensible; shipping it *instead of* the demotion is not.

*(Also **[U]**: whether `DYLD_INSERT_LIBRARIES` interposition could give a raw
count on an ad-hoc-signed binary. Plausible — no hardened runtime — but untested.
No plan should depend on it.)*

---

## 7. Phased plan

Each phase is independently valuable and independently verifiable. **Phase 0
delivers value within a day.**

### Phase 0 — Measure and unblock (XS, hours → 1 day) — DO THIS FIRST

Strategy-assessment item 1, plus the two one-line unblocks. Nothing here needs new
machinery.

| # | Item | Size | Why now |
|---|---|---|---|
| 0.1 | **Re-run the 23-case smoke tier on `--lane macos-native-dsr` at HEAD.** Two-phase, scoped `CARRICK_RUN_ID`, reap with `scripts/sudo/kill.sh`, quiet box. | XS, machine time | Replaces a 12-day-old red number (8/23 gating) with a current one. **This is the gating input to every later phase's scope.** |
| 0.2 | **Fix the native-lane preflight** — split `Lane::MacosNativeDsr` out of the HVF arm at `main.rs:357-368`; give it `preflight_native_darwin()` (exists + freshness-warn + assert not cross-ISA), no codesign check. Drop `conformance-native`'s `: build` dependency. | XS, one `if` | **The single line between the harness and a hosted runner.** |
| 0.3 | **Fix the two RED CI jobs on `main`**: the `platform-freebsd` feature closure (`E0432`/`E0433`), and make `host_proc.rs` **derive** its probe VA instead of hardcoding `0x4_0000_0000`. | S | **CI is red on arrival.** Nothing below can be trusted until it is green. |
| 0.4 | **Add the `BringUp ⟺ routed` test** (§4.5). | XS, ~20 lines | Closes a 34-syscall drift permanently; makes the support level self-maintaining. |
| 0.5 | **Make `ci.yml`'s `check` job call `just ci` verbatim**; pin `macos-15`. | XS | `just ci` and `ci.yml` have already drifted (no `lint-domains`, no `check-matrix`), which falsifies AGENTS.md's "justfile is the single source of truth". |

**Verifiable by:** a current native smoke number committed as an artifact; a green
`main`; `carrick syscalls --number 279` reporting the truth.

### Phase 1 — Guest execution on a hosted runner (S, ~2–3 days)

**Unblocked by:** 0.3 (the `host_proc` fix is what makes the hosted macOS job
green). **Unblocks:** everything else.

- `crates/carrick-runtime/tests/native_darwin_aarch64.rs` + the Darwin arm of
  `run_elf_native_dispatch` (§4.1) + `tests/common/{native_case,cases}.rs` with a
  **watchdog** (C2) and per-lane expectation overlays.
- Add the new binary to `just test-integration`; **add the `carrick-cli` test
  targets to CI** and triage the 39 red ones (C7).
- New hosted `native-acceptance` job with the mandatory `ulimit` preamble (C1) and
  a shell `timeout` on every guest step (C2).
- **Add a manifest test asserting `CASES.len()` matches the per-lane overlay key
  set** — a `#![cfg]`'d test binary that mis-cfgs compiles to zero tests and
  reports `ok`.

**Verifiable by:** a hosted GitHub run that executes a real Linux ELF, with the
job **observed red** first (revert the handler, watch it fail, restore).

### Phase 2 — The ecosystem-test class (M, ~1 week)

**Unblocked by:** Phase 1 + 0.2.

- `KvParser` (§4.3); `Suite { syscalls, amplify }`; `suites.ecosystem.toml` +
  multi-manifest load; `just new-ecosystem-test` / `gen-ecosystem-suites`;
  **a golden test proving `OracleKey` did not move**.
- Hosted `oracle-refresh` job on `ubuntu-24.04-arm` (ecosystem manifest only,
  opens a PR).
- Seed **10–15 tests against the known native-lane gaps first** — CPython
  fork-in-thread, `subprocess` throughput, go `os/exec`, and the 37 zero-coverage
  BringUp syscalls (§4.4). **Skip node `worker_threads` (C4) and `cat` (C3).**
- Hosted `native-ecosystem` job, **report-only**.

**Verifiable by:** a contributor running the §4.6 worked example end-to-end.

### Phase 3 — Make green mean something (S–M, ~3–5 days)

**Unblocked by:** Phase 2. **Blocks:** any hard gate anywhere.

- `--require-oracle` + run-free `--check-oracle-coverage` (H1).
- Ecosystem-manifest policy: **NEW and DIFF gate; a missing baseline row on a
  hand-authored test is a failure** (H2/H3/H5).
- Audit the 66 blanket `known_gaps=["summary"]` LTP suites (H4).
- Every new `check-*` asserts a non-zero comparison count.
- Stamp `docs/support-matrix.md` with lane/backend/commit/date.

**Verifiable by:** deliberately deleting an oracle line and watching the gate go
red; deliberately breaking one assertion and watching NEW gate.

### Phase 4 — The fleet join key + aggregator (M, ~1 week)

**Unblocked by:** Phase 3 (rows must be trustworthy before they are joined).

- `SuiteReport += env/exercised/hostops`; `EnvKey`; `fleet.rs`; the three renders
  and their drift gates; `just fleet`; `--require-lane`; the
  `fleet-aggregate` job with `if: always()`.

**Verifiable by:** a matrix that correctly shows four lanes `unproven` on a fresh
Mac, and a non-zero exit when `--require-lane` names an absent lane.

### Phase 5 — The counters (M–L, ~1–2 weeks)

**Unblocked by:** Phase 4 (`exercised` needs the record) **and** Phase 2 (the
ratchet needs workloads to measure). **This is where the ratchet lands, and it
lands here because it cannot land earlier.**

- `carrick-observability/src/perf.rs`, per-thread, merge-at-exit, typed
  (`CanonicalNr` keys, `HostOpCount` newtype, ordinal `HostOpDomain`) per the
  typed-domain rule.
- The two-line `reporter.finish()` wiring (§6.3 correction 2).
- `hostcall::fs` first; `essential`/`retries` split; per-pid emission summed over
  the tree.
- **Back-to-back overhead measurement against an uninstrumented build. Revert if
  it does not pay.**
- `amplification.jsonl`, `just amplify-bless --reason`, `just
  check-amplification`, N=3 self-policing, the 20× stability run.
- **Report-only.** Promote per §6.7's six criteria.

### Phase 6 — Root-cause the number (L, a campaign)

`docs/cap-std-demotion-plan.md`, so the logical count becomes the raw count and
the 291× figure is finally gate-able (§6.8).

### Dependency summary

```
0.3 (green CI) ──► Phase 1 (hosted guest exec) ──► Phase 2 (ecosystem class) ──► Phase 3 (gate semantics)
0.2 (preflight if) ──────────────────────────────►                                      │
0.1 (the number)  ──► scopes Phases 2 & 5                                               ▼
0.4 (BringUp⟺routed) ──► makes §4.4's syscall axis honest              Phase 4 (fleet join key)
                                                                                        │
                                                                                        ▼
                                                                          Phase 5 (counters + ratchet)
                                                                                        │
                                                                                        ▼
                                                                          Phase 6 (cap-std demotion)
```

---

## 8. Risks and open questions

### 8.1 What could make hosted-runner guest execution flaky

*A flake in CI is worse than no CI, given the project's absolute determinism
standard.* Ranked:

| # | Risk | Mitigation |
|---|---|---|
| **R1** | **3 vCPU / 7 GB vs a 10-core dev Mac.** **[E]** carrick is 13.5× the oracle on go-errors and >25× on cpython-subprocess; the lane already carries `timeout_scale 5.0`, and **[U]** whether that suffices on 3 cores. **A load-coupled TIMEOUT verdict is the classic way to bisect onto the wrong commit.** | **The in-flight uncommitted `classify_timeout` work is exactly the right mitigation** (§7.6) — `TimeoutKind::Starved` marks a run as a **measurement failure, not a carrick failure**. Land it *before* the hosted ecosystem job. Also: keep hosted scope at smoke; never gate on wall-clock; sample ≥2× before believing a flip. |
| **R2** | **C2 + C3 together: unbounded hang and unbounded stdout.** `DEFAULT_MAX_TRAPS` removal turned a diagnosable abort into a 6-hour job. | Shell `timeout` on every guest step; prefer the harness (which has a per-suite deadline + scoped kill) over hand-written `carrick run` steps; **fix the `cat` EOF bug**; consider a native-lane progress-aware watchdog mirroring `vcpu_loop/mod.rs`. |
| **R3** | **C1 fd limits**, whose failure mode is a *lying errno* (EMFILE surfaced as `netpoll failed`). | Mandatory `sysctl` + `ulimit -n 65536` preamble in every guest step; treat 2048 as insufficient. |
| **R4** | **C8 case-insensitive scratch degrades silently** — worst possible place for an ecosystem lane (Go trees, `node_modules`). | An explicit **assertion** step (not a best-effort `\|\| true`) that the scratch root is case-sensitive, or a recorded, reviewed decision to run degraded. Settle open question (4) first. |
| **R5** | **C11 anonymous Docker Hub pulls** rate-limited on shared runner egress IPs. | GHCR, or `carrick login` with a token. Digest-pinning helps caching but not the limit. |
| **R6** | **C9 disk.** 14 GB against a 1.3 GB target dir + images + leaked scratch. | Purge scratch between steps; keep hosted images small and public; never pull the four big conformance images on a hosted runner. |
| **R7** | **Hosted image drift.** GitHub rotates runner images monthly; **[E]** the `host_proc.rs` failure proves carrick has host-layout assumptions that differ across macOS versions. | Pin `macos-15` explicitly (never `macos-latest`); make fixed-VA code derive rather than hardcode; treat a runner-image bump as a reviewed change. |

### 8.2 Honest maintenance cost

- **Recurring per new test:** one `oracle-cache.jsonl` line (mechanical,
  `--refresh-oracle`) + one `amplification.jsonl` line + one `Case` literal. Small.
- **Recurring per instrumentation change:** growing `hostcall` coverage changes
  `instrumented_domains`, which **invalidates comparisons by design** and forces a
  re-bless. Real, recurring, and correct — but it means schema changes are a
  planned event, not a drive-by.
- **New committed artifacts:** 3 rendered docs + N baselines + 4–6 new `check-*`
  recipes. **Adding gates to an already-drifted pair makes it worse** — hence 0.5
  (`ci.yml` calls `just ci`) is a *prerequisite*, not a nicety.
- **Avoided cost:** today's ~12-file hand-touch list per syscall, of which this
  design mechanises three (support map, coverage doc, matrix) and gates a fourth
  (`SupportLevel`).
- **Two docs become generated** that are hand-written today
  (`syscalls-emulation-map.md` is ungenerated, ungated and 23 days stale;
  `conformance-coverage.md`'s metric script isn't wired into any gate and **[V]**
  `scripts/coverage-metric.py:112` returns 0 while 283 probes are undocumented,
  contradicting `docs/conformance-testing.md:181`'s claim that it fails in that
  case).

### 8.3 Amplification-measurement overhead distorting what it measures

The sharpest self-referential risk. A per-syscall counter on a runtime with a
~1.8 µs trap floor and a ~3.5 µs guest-stat fast path can cost more than it
measures, and **[V]** two commits from the last perf campaign were reverted for
being net-negative. Mitigations, in order: per-thread arrays with no hot-path
atomics; merge only at process exit; **a mandatory back-to-back measurement
against an uninstrumented build before it lands, with revert as the default
outcome if it does not pay**; and — because the counters are cheap only when
nobody is listening — keep the USDT probe path (which **[V]** costs one
predicted-not-taken branch when unconsumed) as the zero-overhead default and the
counters behind the env gate.

### 8.4 Open questions needing a maintainer ruling

1. **Does the native lane actually run on GitHub's macOS image?** (§1.4 item 2.)
   Everything rests on this and it cannot be settled locally. **Cost: one
   throwaway workflow.** Do it before Phase 1.
2. **`/dev/kvm` on hosted `ubuntu-latest`?** Decides whether the amd64
   `kvm-local` lane becomes a second free hosted guest lane. **[I]** only. **Cost:
   one throwaway workflow doing `ls -l /dev/kvm`.**
3. **`diskutil apfs addVolume` inside a hosted runner VM?** Decides R4. If it
   fails, rule explicitly whether a degraded case-insensitive ecosystem lane is
   acceptable (and record it), rather than letting `apfs.rs:322-326` decide
   silently.
4. **Publish the four conformance images to GHCR, or keep hosted CI to the
   ecosystem manifest only?** This design assumes the latter (§2 item 3). ~4.7 GB
   of blobs and a 14 GB runner argue for it; a desire to run LTP on hosted CI
   argues against.
5. **Is the hosted-Linux Docker oracle allowed to become authoritative for the
   *new* manifest?** This design says yes for ecosystem suites, **never** for
   `baseline.jsonl` (different kernel from Docker Desktop's LinuxKit ⇒ verdicts
   move). Confirm.
6. **Should `bless_target()`'s authority invert** so the native lane can write
   `baseline.jsonl` and `docs/support-matrix.md`? The strategy assessment
   explicitly declines to recommend this as bounded work (native's own checklist
   is 2/14 with two open P0s). This design **follows that** — native gets a
   first-class overlay and its own renders, not the shared baseline — but it is
   the maintainer's call and it changes what "primary backend" means in the repo.
7. **Node on the native lane** (C4): fix the DSR `LDP` writeback gap, or exclude
   node from the hosted ecosystem set and say so in the docs? Currently the
   ecosystem with the thinnest coverage (3 suites) and a known red.
8. **The `syscall.rs:158-159` UAPI provenance comment** attributes the aarch64
   table to a kernel header, contradicting AGENTS.md's non-negotiable clean-room
   rule. The strategy assessment flags it; it should be resolved before any of
   this is externally visible, and this program makes the syscall table more
   prominent, not less.

### 8.5 A note on the uncommitted working-tree change

`crates/carrick-conformance/src/{engine,main,oracle,verdict}.rs` currently carry an
unmerged `TimeoutKind` / `classify_timeout` feature that classifies a missed
deadline as `Spinning` / `Starved` / `Blocked` / `Unknown` from a pre-kill CPU
sample plus load average, with `is_measurement_failure()` true for `Starved`.

**This is directly load-bearing for R1 and should be sequenced into Phase 0.**
A 3-vCPU shared hosted runner is the single most likely place for a starved
verdict, and without this the hosted ecosystem lane would record box contention as
carrick regressions — the exact failure the project already hit when a healthy
`kill10` "timed out" at ~suite 1000 purely because leaked guests had degraded the
box. Land it before the hosted ecosystem job, not after.
