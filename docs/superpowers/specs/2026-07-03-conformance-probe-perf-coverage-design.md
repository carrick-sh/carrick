# Conformance-probe performance coverage: host-op amplification

**Status:** design (2026-07-03)
**Author:** Timothy J Fontaine (with Claude)

## Goal

Turn the one-off amplification investigation in
[`docs/fs-host-capstd-amplification.md`](../../fs-host-capstd-amplification.md)
— which used `carrick trace`/dtrace to find that `--fs host` issues **~291 host
`open()`s per guest `openat`** — into a **standing, always-on signal** attached
to every conformance probe.

For each probe we want to answer, deterministically and without any external
tooling:

1. **How many host operations does carrick issue** while servicing that probe's
   guest Linux syscalls?
2. **What is the amplification** — host-ops per guest Linux syscall — so a
   regression ("this change made us do more work per syscall") is caught
   mechanically, and a pathological absolute ratio (host-ops far exceeding the
   guest syscalls the probe actually ran) is visible?
3. **How long did it take** (wallclock), as a reported trend.

The amplification ratio is our operationalization of "are we over what Linux
itself does": carrick dispatches the guest Linux syscalls, so it *already knows*
the guest syscall count; the seam gives the host-op count; the ratio is intrinsic
and needs no Linux/Docker reference.

## Non-goals

- **Raw host-syscall counts.** We count *logical* host operations that carrick's
  own code issues (one bump per carrick host-operation). We do **not** count the
  raw `libc` syscalls a dependency issues internally — e.g. cap-std's
  per-component path walk that turns one carrick open into ~45 raw `openat`s. That
  intra-library multiplication is the domain of the existing `carrick trace`/dtrace
  deep-dive and stays separate (see Future work).
- **A Linux differential.** No `strace`, no Docker-side syscall counting. `strace`
  under the arm64 Docker-in-LinuxKit oracle is unreliable, and the intrinsic ratio
  already gives the amplification signal. This keeps the whole system Docker-free,
  deterministic, and gate-able everywhere (including the KVM/bhyve/NVMM lanes).
- **Gating on time.** Wallclock is recorded and rendered as a trend; it is never a
  gate trigger (it is host- and load-variable).

## Architecture

Six units, each with one purpose. The first is the only real build; the rest copy
the machinery we already have for the support matrix (`baseline.jsonl` +
`just check-matrix` + `matrix.rs` render).

### 1. `hostcall` accounting seam (the load-bearing work)

A thin module that carrick's host operations route through, grouped by domain:
`fs`, `net`, `mem`, `proc`. Each wrapper does the real host operation and records
one **logical host-op** against the current dispatch context.

- **Interface:** `hostcall::fs::openat(...)`, `hostcall::fs::fstatat(...)`,
  `hostcall::net::sendto(...)`, etc. — 1:1 with the host operation, returning the
  same result/errno the raw call would. Internally each calls
  `perf::record(Domain::Fs)` then performs the op.
- **Dependency:** `carrick-observability` (holds the counter; see unit 3). No new
  crate.
- **Coverage is incremental.** There are ~132 scattered `libc::` sites across 51
  runtime files; routing them through `hostcall` is a migration, not a big-bang.
  Land the seam + **instrument `fs_backend.rs` first** (the known amplifier and the
  highest-value target — the redundant `symlink_metadata`, the per-stat xattr
  reads, the double open-RW-then-RO the amplification doc catalogs), then net, then
  mem/proc. A probe's count reflects *instrumented* coverage; uninstrumented sites
  read as zero until routed. The perf-baseline is only meaningful for the domains
  already routed, and the render marks a probe's counted domains explicitly so a
  zero is never mistaken for "no work."

### 2. Per-dispatch attribution

`SyscallDispatcher::dispatch(request)` (`dispatch/mod.rs:2236`) is the single
per-guest-syscall chokepoint; `request.number` is a typed `CanonicalNr`.

- A `thread_local! CURRENT_NR: Cell<Option<CanonicalNr>>`.
- `dispatch()` sets `CURRENT_NR = Some(request.number)` via an RAII guard for the
  duration of the call, and increments a process-wide `invocations[nr]` counter.
- `perf::record(domain)` bumps the process-wide `host_ops[nr][domain]` for
  `CURRENT_NR`. Host-ops issued with `CURRENT_NR == None` (boot, teardown, trap
  loop) accrue to an `overhead` bucket, never mis-attributed to a guest syscall.
- Process-wide counters are atomic (carrick is multi-threaded: one vCPU thread per
  guest thread, each dispatching). Attribution is per-`CanonicalNr` totals across
  the whole run — no per-invocation deltas needed, since each `record` bumps the
  live `CURRENT_NR` bucket directly.

### 3. Per-probe aggregation + report emission

Mirrors the existing `compat-report` in `carrick-observability`: carrick
accumulates in-process and emits a JSON summary at exit when asked.

- Env-gated: `CARRICK_PERF_REPORT=<path>` (like the compat reporter). Off by
  default → zero overhead in normal runs (the `record` bump is a single relaxed
  atomic add, cheap enough to always compile in; the *emission* is env-gated).
- At guest exit, carrick writes (counts are *logical* carrick host-ops — one bump
  per carrick host operation, e.g. the ~6 cap-std calls a `--fs host` open makes,
  not the raw syscalls cap-std issues internally):
  ```json
  {
    "total_host_ops": 18, "total_guest_syscalls": 3, "amplification": 6.0,
    "wallclock_ms": 12.4, "overhead_ops": 5,
    "per_syscall": [
      {"nr": 56, "name": "openat", "invocations": 3, "host_ops": 18,
       "by_domain": {"fs": 18}, "ratio": 6.0}
    ]
  }
  ```
- The harness runs each probe with `CARRICK_PERF_REPORT` set and reads this back.

### 4. Storage — `scripts/conformance/perf-baseline.jsonl`

One committed record per probe, same shape as the emitted report plus the probe
name and the set of instrumented domains it exercised. This is the ground truth
the gate compares against and the render reads — exactly analogous to
`baseline.jsonl` for the conformance matrix.

### 5. `just check-perf` — the deterministic gate (in `just ci`)

- Re-runs the probes under carrick with `CARRICK_PERF_REPORT`, compares against the
  committed `perf-baseline.jsonl`.
- **Fails** when a probe's `total_host_ops` (or any per-syscall `host_ops`)
  **regresses** beyond a tolerance — default: an increase of more than
  `max(2, ceil(0.10 * baseline))` ops (absolute floor + 10%), tunable per record
  via an optional `tolerance` field. A *decrease* never fails (improvements are
  free); it just flags the baseline as stale-low for re-bless.
- **`amplification` ratio** is compared the same way and can carry an optional
  absolute **ceiling** per probe (`max_ratio`) that flags — report-only, does not
  fail CI — any probe over it (default advisory ceiling 10×).
- **Wallclock** is recorded in the fresh run and rendered, **never gated**.
- No Docker, no oracle, no HVF-guest-under-Docker concurrency concern — pure
  carrick re-run. Wired into `just ci` beside `check-matrix`.

### 6. Refresh + render

- **Refresh** (`just perf-bless` or a flag): re-run probes under carrick, rewrite
  `perf-baseline.jsonl`. Carrick-only — far lighter than the matrix bless (no
  Docker phase). Because counts are deterministic, a clean re-bless is a byte-stable
  no-op unless real behavior changed.
- **Render** (`docs/perf-matrix.md`, or a section appended by `matrix.rs`): per
  probe — total host-ops, amplification ratio, Δ-vs-baseline, top amplifying
  syscall, wallclock trend, and the counted domains. `git diff` on this file is the
  perf review, same principle as the support matrix.

## Data flow

```
guest syscall ──▶ dispatch(request)  [sets CURRENT_NR = request.number,
                                       invocations[nr] += 1]
                       │
                       ├─▶ hostcall::fs::openat(...) ─▶ perf::record(Fs)
                       │        [host_ops[CURRENT_NR][Fs] += 1]  (× however many)
                       └─▶ ...
guest exit ──▶ CARRICK_PERF_REPORT written (per-nr aggregate + wallclock)
                       │
harness ──▶ reads report ──▶ perf-baseline.jsonl / check-perf compare / render
```

## Testing strategy

- **Unit (carrick-observability):** the counter aggregates per `CanonicalNr`,
  attributes `None`-context bumps to `overhead`, is atomic across threads, and
  emits stable JSON. No HVF/guest needed.
- **Unit (dispatch):** the RAII guard sets/clears `CURRENT_NR` and survives early
  returns / errors on every dispatch exit path.
- **Integration (harness):** a fixture probe with a known, fixed host-op count
  (e.g. one that does N `openat`s through the instrumented `fs` seam) produces the
  expected `perf-baseline` record; `check-perf` passes on match, fails on a seeded
  regression (red-first).
- **Determinism:** two back-to-back refreshes of the same probe produce
  byte-identical counts (ratio/counts, not wallclock).

## Coverage & rollout

Land in order, each independently useful:

1. Seam + attribution + observability counter + report emission (no call-sites
   routed yet → all zero, but the plumbing lands and is tested).
2. Route `fs_backend.rs` through `hostcall::fs` — immediate signal on the marquee
   amplifier.
3. `perf-baseline.jsonl` + `just check-perf` + render, bless the fs numbers.
4. Route `net`, then `mem`/`proc`, re-blessing as coverage grows.

## Future work (explicitly out of scope here)

- **Raw-count deep mode.** When a probe's *logical* count looks fine but the fs
  cost is still high, the amplification lives inside a dependency (cap-std). That
  is caught by the existing `carrick trace`/dtrace scripts
  (`scripts/dtrace/glob-openat-drill.d`); a future opt-in could drive them per-probe
  for a raw host-syscall number. Kept separate — it is macOS/sudo/dtrace-bound,
  which this design deliberately avoids for the always-on gate.
