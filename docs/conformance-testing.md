# Carrick conformance testing

Carrick proves Linux-ABI fidelity along two axes, and you run them with different
commands for different reasons:

* **Compile-time conformance** — structural ABI invariants (struct sizes, field
  offsets, constant uniqueness, the syscall-table ordering) are pinned by
  `const _: () = assert!(...)` items the *compiler* evaluates. A drift fails the
  *build* with a named message. These cost nothing at runtime and need no HVF,
  no Docker, no signed binary.
* **Runtime conformance** — observable behavior is pinned by differential tests
  that run an identical workload under carrick and under a real Linux
  `linux/arm64` container (the Docker oracle) and diff the output. These need the
  signed release binary and a reachable Docker daemon.

Compile-time checks pin *what the bytes are*; runtime probes pin *what the
syscall does*. Both are gates: a green build plus a green probe suite is the
contract.

The active runtime gate and its probe-to-invariant mapping live in
[conformance-coverage.md](conformance-coverage.md); this document is the
how-to-run-and-interpret companion.

---

## Host unit/integration tests

The fast inner loop. Pure-Rust library tests across the workspace — VFS logic,
ABI encoders, sockaddr translation, the in-memory rootfs merge — with **no HVF
vCPU and no Docker**:

```sh
just test                      # == cargo test --workspace --lib
cargo test --workspace --lib   # the same thing, directly
```

`--lib` deliberately scopes to the in-crate `#[cfg(test)]` modules and skips the
integration-test binaries under `crates/carrick-cli/tests/` (which need the
signed binary and Docker — see below). Because these tests never spawn a guest,
they run from a plain `cargo build` artifact and stay green on any machine.

> [!NOTE]
> The crate-wide no-panic gate (`unwrap`/`expect`/`panic!`/`todo!`/
> `unimplemented!` denied) is enforced separately by clippy, not the test
> runner: `just clippy` (== `cargo clippy --workspace --all-targets -- -D
> warnings`). Test code is exempt via `clippy.toml`. The compile-time
> conformance asserts below are `const` items, never reachable code, so they do
> **not** trip this gate.

---

## Differential probe suite vs Docker

The runtime ABI gate. It lives in `crates/carrick-cli/tests/conformance.rs` and
runs deliberately:

```sh
just conformance                                              # builds+signs, then runs
cargo test -p carrick-cli --test conformance -- --nocapture   # if already built+signed
```

`just conformance` depends on `build`, so it always re-signs the release binary
first ([`scripts/build-signed.sh`](../scripts/build-signed.sh)). `--nocapture`
surfaces the per-case `PASS`/`FAIL`/`XFAIL` lines as they run.

### What a case is

The suite has three flavors of differential case, all sharing the same
carrick-vs-Docker diff engine:

* **Shell snippets** (`CASES`) — a `/bin/sh -c` snippet (e.g. `uname -m`,
  `stat -c '%s %F %a' /etc/passwd`, `cd /tmp && ln -sf … && readlink lnk`) run
  under `carrick run --raw --fs host` and inside the `linux/arm64` container,
  byte-diffed after a `normalize()` pass that strips carrick's host-side scratch
  notices. A diff is a candidate syscall gap *surfaced by name* — `dpkg returned
  100` becomes `FAIL arm64:stat`.
* **Probe binaries** (`conformance_probes`) — static `aarch64-unknown-linux-musl`
  ELFs under `conformance-probes/` that each print one deterministic line per
  observation. The harness base64-encodes the probe, pipes it to the guest's
  stdin, and the child does `base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p` —
  the same snippet under carrick and Docker. Build them with
  [`scripts/build-probes.sh`](../scripts/build-probes.sh) (a `rust:alpine`
  container cross-builds the static musl ELFs); without them the probe test
  self-skips.
* **Default-run contract** (`conformance_default_run_contract`) — asserts the
  *default* `carrick run` path (no `--raw`) is docker-shaped: exit-code parity,
  stdout/stderr separation, no JSON envelope on stdout.

The same two-sided run also drives `conformance_go_fixture` (a Go hello-world
ELF built by `scripts/build-go-fixtures.sh`).

### Self-skip semantics

Every `#[test]` here **passes by skipping** when its prerequisites are absent, so
`cargo test` stays green on a machine without HVF entitlement or Docker:

* `target/release/carrick` missing → `SKIP … not built`.
* Docker unreachable (`docker version` / bollard `ping` fails) → `SKIP …`.
* Probe ELFs not built for the lane → `SKIP conformance_probes[...]`.
* The `linux/amd64` Rosetta lane skips unless Rosetta-for-Linux is installed;
  static-musl probes only run on the `arm64` lane.

A genuine ABI divergence is the only thing that turns a non-skipped case red.

### Two-phase, parallel, never carrick‖docker

> [!WARNING]
> Carrick (an HVF guest) and the Docker oracle (a LinuxKit VM) **starve each
> other** when run concurrently — slow runs and false TIMEOUTs on
> timing-sensitive probes. The gate is therefore strictly **two-phase**: phase 1
> fans out *all* carrick runs across a worker pool, phase 2 fans out *all* Docker
> runs, phase 3 classifies (runs nothing). `carrick‖carrick` and `docker‖docker`
> are fine and are where the speed comes from; `carrick‖docker` is never allowed.

The pool is sized `min(cores-2, 8)`. Each case is hermetic: a per-case
`CARRICK_RUN_ID` is stamped into the guest's process title, so timeout cleanup
([`scripts/sudo/kill.sh`](../scripts/sudo/kill.sh)) reaps *only* that case's
guest tree — concurrent lanes and worktrees never reap each other. A
`CASE_DEADLINE` of 45 s SIGKILLs a wedged guest and marks the case
`FAIL(timeout)` so one stuck process can't stall the run.

Timing-sensitive probes (`futex*`, `posixtimers`, `itimer`, `iouring`,
`sigchld`, …, see `TIMING_SENSITIVE_PROBES`) are quarantined to a *serial tail*
after the parallel batch, because they flake under concurrent CPU load (the
macOS `__ulock` zombie-wake window, host scheduling tail-latency).

### Reading the verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | carrick and Linux produced identical output. |
| `FAIL` | a divergence (or a docker error/timeout). The diff is printed line-by-line (`- carrick:` / `+ linux:`) so the offending syscall is pinpointed. |
| `XFAIL` | a *known, tracked* gap listed in `KNOWN_PROBE_GAPS` (each entry cites its milestone). The suite stays green; the divergence is expected. |
| `UNEXPECTED PASS` | a `KNOWN_PROBE_GAPS` probe started passing — the gap is fixed. The suite **fails loudly** so the stale entry gets removed. |

A handful of reducers that hard-wedge or only reproduce under contention live in
`GATE_SKIP_PROBES` (e.g. `forksleepfork`, `manythreads`) — run those by hand with
[`scripts/run-probe.sh <name>`](../scripts/run-probe.sh), which mirrors the gate's
exact path (base64-onto-stdin, threaded run-loop) rather than the lighter
`run-elf` path.

### The headline coverage number

```sh
python3 scripts/coverage-metric.py
```

parses [conformance-coverage.md](conformance-coverage.md) plus the probe binaries
on disk and reports how complete the owned-probe gate is — owned invariant
probes, invariant rows with an owning ✅/🧪 test, distinct curated LTP tests stood
in for. It also fails if the doc cites a probe that doesn't exist on disk, or a
probe on disk goes undocumented. This is the metric the project tracks *instead
of* a raw "LTP MATCH count": LTP-in-Docker is the discovery oracle; a probe is
the durable gate.

---

## Language-runtime conformance suites

A coarser axis than the probe map: end-to-end differential runs of real language
test suites under `carrick run` vs the Docker `linux/arm64` oracle (same image,
same args, outcome-category diff). These are *discovery* runs — a confirmed gap
should graduate to an owned probe row.

> [!IMPORTANT]
> Run each heavy suite **solo**. Concurrent heavy suites (or a suite running
> alongside the probe gate) starve the host and produce false TIMEOUT / `n=0`
> results that look like mass regressions but aren't.

* **Go** — [`scripts/go-conformance.sh`](../scripts/go-conformance.sh) builds the
  Go std-library test binaries (external-static-pie, via `golang:1.24-bookworm`)
  and runs each under carrick and under a Docker arm64 container, reporting tests
  that pass under Docker but fail/are-absent under carrick. Process/exec-surface
  packages (`os/signal`, `os/exec`) run inside a coherent `debian:stable-slim`
  rootfs rather than the bare `--fs host` scratch. The prebaked-image wrapper is
  [`scripts/go-conformance-image.sh`](../scripts/go-conformance-image.sh)
  (`localhost:5005/carrick-go-conformance:1.24`).
* **Node.js** — [`scripts/nodejs-conformance-image.sh`](../scripts/nodejs-conformance-image.sh)
  wraps the suite runner (`localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`),
  covering `node-core`, `libuv`, `v8-smoke`, `npm-smoke`, `app-smoke`. Under
  carrick the suites run via the image's native entrypoint, e.g.
  `carrick run --raw --entrypoint /bin/bash <image> /usr/local/bin/nodejs-conformance
  --runner carrick --suite <suite>` (a `#!` script entrypoint is honored by
  carrick's execve/shebang support).
* **CPython** — [`scripts/cpython-parity.py`](../scripts/cpython-parity.py) runs
  `python3 -m test -v --randseed 0 <module>` under both Docker and carrick with
  the matching `Lib/test` mounted in, parses the unittest verbose output into a
  `{test_id: outcome}` map per side, and diffs *outcome categories* (never
  timings/tracebacks — deterministic by construction). Per-module verdicts land
  in `docs/cpython-baseline/`.

> [!NOTE]
> `cpython-parity.py --jsonl` *appends* — dedupe last-wins per module when
> reading the file back.

---

## Local registries

Carrick auto-pulls an image it doesn't have cached. The conformance images live
in two **insecure local registries**:

| Registry | Holds |
|---|---|
| `localhost:5050` | LTP + probe images, and the baked CPython test image (e.g. `localhost:5050/cpython-test:3.12.13`). |
| `localhost:5005` | Language-suite images (`carrick-go-conformance`, `carrick-nodejs-conformance`). |

Carrick will not pull from a plain HTTP registry unless you allow it:

```sh
export CARRICK_INSECURE_REGISTRIES=localhost:5050      # or localhost:5005
```

The helper scripts set this for you (`run-probe.sh`/`cpython-parity.py` default
to `:5050`, `go-conformance-image.sh` to `:5005`).

> [!WARNING]
> CPython parity needs the **registry** ref `localhost:5050/cpython-test:3.12.13`,
> not a bare docker-daemon image tag. A bare ref → carrick can't pull → every
> module reports `n=0` and looks like a mass regression that isn't. (Port note:
> the registry is on `:5050`, not `:5000` — macOS ControlCenter holds `:5000`.)

---

## Compile-time conformance checks

The structural-ABI gate. Linux's kernel ABI fixes the byte layout of every
struct that crosses the syscall boundary and the numeric value of every constant
carrick translates. A silent drift — a reordered field, a wrong `size_of`, two
signal numbers that collide, a syscall-table row out of order — would corrupt
guest memory or quietly mis-dispatch at runtime. Carrick pins these as
**compile-time assertions**, so the drift fails the *build* instead.

### The mechanism

A `const _: () = assert!(<condition>, "<message>")` item is evaluated by the
compiler during const-folding. If the condition is false the build aborts with
the named message; if true the item compiles to nothing. It is **never reachable
at runtime**, so it is invisible to the crate-wide no-panic clippy gate — the
same reason these are safe to scatter liberally. Field offsets use the
const-stable `core::mem::offset_of!`; sizes use `core::mem::size_of`.

### Struct layout: `kernel_abi!` and `assert_layout!`

Two macros in `crates/carrick-abi/src/lib.rs`:

* `kernel_abi!($ty, $size, $why)` (`crates/carrick-abi/src/lib.rs:1241`) pins a
  struct's `ABI_SIZE` (and asserts it never exceeds `size_of`, which would
  over-read guest memory). Applied to ~30 UAPI structs: `LinuxStat` (128),
  `LinuxStatx` (256), `LinuxCloneArgs` (88), `LinuxMsghdr` (56),
  `LinuxSigaction` (32), `LinuxTermios`, `LinuxRlimit`, the timer/time structs,
  and more.
* `assert_layout!($ty, size = N, field @ off, …)` (`crates/carrick-abi/src/lib.rs:1274`)
  pins `size_of` *and* exact field offsets. It runs over the structs whose field
  positions are load-bearing — `LinuxMsghdr` (`name @ 0, namelen @ 8, iov @ 16,
  …`), `LinuxCloneArgs` (`flags @ 0, stack @ 40, tls @ 56`), the aarch64
  `rt_sigframe` chain (`LinuxSiginfo`, `LinuxSignalContext` `size = 4384`,
  `LinuxUcontext` `size = 4560`, `CarrickSigframe`, `LinuxFpsimdContext`
  `size = 528`), the io_uring ring structs (`LinuxIoUringSqe` 64,
  `LinuxIoUringCqe` 16, `LinuxIoUringParams` 120), `LinuxStat`, `LinuxIovec`,
  `LinuxEpollEvent`, `LinuxPollFd` (`crates/carrick-abi/src/lib.rs:2376`
  onward).

A wrong offset on, say, `LinuxStat.st_size` would have crashed glibc with a
garbage file size; now it's a build error: `LinuxStat.st_size: field offset
mismatch vs Linux aarch64 ABI`.

### Constant uniqueness / disjointness

Five `const _: () = { … }` blocks at `crates/carrick-abi/src/lib.rs:2424`
onward each loop a fixed array at const-eval time and assert an invariant:

* **`LINUX_SIG*`** — every signal number is unique *and* within the kernel's
  `1..=31` range.
* **`LINUX_AF_*`** — the address families carrick translates are pairwise
  distinct.
* **`LINUX_SOCK_*`** — socket types are pairwise distinct.
* **`LINUX_SA_*`** — the `sa_flags` bits carrick honors occupy *disjoint* bit
  positions (an overlap would make one flag silently imply another in
  `rt_sigaction`).
* **`LINUX_CLONE_NEW*`** — the namespace-creation clone flag bits are disjoint.

A duplicate or overlapping constant — invisible by inspection — becomes
`duplicate Linux signal number` / `Linux sa_flags bits overlap` at build time.

### Syscall-table ordering

`AARCH64_SYSCALLS` in `crates/carrick-hvf/src/syscall.rs` is looked up via
`binary_search_by_key` on the syscall number, which is only correct if the table
is strictly sorted. A `const _: () = { … }` guard at
`crates/carrick-hvf/src/syscall.rs:536` walks the table at compile time and
asserts each row's number is strictly greater than the previous — guaranteeing
both binary-search validity and number uniqueness. Insert a row out of order and
the build fails:

```
error[E0080]: evaluation of constant value failed
  --> crates/carrick-hvf/src/syscall.rs:539:9
   |
539 | /         assert!(
540 | |             AARCH64_SYSCALLS[i - 1].number < AARCH64_SYSCALLS[i].number,
541 | |             "AARCH64_SYSCALLS must stay strictly sorted by syscall number \
542 | |              (binary_search validity + number uniqueness)",
   | |_________________________________________________________^ the evaluated program panicked
```

All of these fire on a bare `cargo build` / `cargo check` — no HVF, no Docker, no
signing — so they catch ABI drift the instant it compiles, long before any
runtime probe runs.

---

## Hermetic-run tips

> [!IMPORTANT]
> A guest only runs from a **codesigned** binary. `cargo build` strips the
> `com.apple.security.hypervisor` entitlement on macOS, so a bare build fails
> *every* guest run with `HV_DENIED` (`0xfae94007`) — the dominant source of
> conformance "flakiness". Use `just build` (==
> [`scripts/build-signed.sh`](../scripts/build-signed.sh)), which re-applies the
> entitlement after linking. Use plain `cargo build`/`cargo test` only for
> compile-checking and the host `--lib` tests, never to run a guest.

The conformance harness defends against this anyway: `ensure_signed()` re-signs
the binary in place (idempotently) before any guest run, and surfaces a signing
failure loudly rather than degrading into a silent `HV_DENIED`.

* **Build the probes first.** `just conformance` builds+signs the binary but does
  *not* build the probe ELFs — run [`scripts/build-probes.sh`](../scripts/build-probes.sh)
  once (or the `conformance_probes` test self-skips with `probes not built`).
* **Run heavy suites solo.** The language suites and the probe gate each
  oversubscribe the host; running two at once produces false TIMEOUT / `n=0`. The
  probe gate already serializes its own carrick/docker phases, but it should not
  share the machine with a concurrent docker oracle or a second language suite.
* **Kill stray guests before tracing/re-running.** A wedged `carrick run` from a
  prior run holds a vCPU; reap it (`scripts/sudo/kill.sh <run-id>`, or
  `pkill -9 -f 'carrick:<run-id>'`) before the next pass.

---

## See also

* [conformance-coverage.md](conformance-coverage.md) — the active probe→invariant
  map and the headline coverage number.
* [diagnostics-and-debugging.md](diagnostics-and-debugging.md) — `carrick trace`,
  the event ring, the carrick-lldb plugin, and the env vars (`CARRICK_RUN_ID`,
  `CARRICK_INSECURE_REGISTRIES`, …) used above.
* [architecture-overview.md](architecture-overview.md) — the HVF trap boundary,
  paging, and scheduling model the ABI structs and syscall table feed.
* [syscalls-emulation-map.md](syscalls-emulation-map.md) — the per-syscall
  support map behind `AARCH64_SYSCALLS`.
* [../README.md](../README.md) — quickstart and the `just` recipe index.
