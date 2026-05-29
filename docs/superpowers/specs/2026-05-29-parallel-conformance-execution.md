# Parallel execution of the conformance gate

> Status: design note (no code yet). Captures how to parallelize the
> `cargo test --release -p carrick-cli --test conformance conformance_probes`
> sweep, which is serial today (~130s for ~70 probes).

## Why it's serial today

`crates/carrick-cli/tests/conformance.rs` runs each probe case as: spawn
`carrick run ubuntu:24.04 --raw --fs host /bin/sh -c '<base64 probe + run>'`,
spawn the Docker linux/arm64 oracle, line-diff the two outputs. A shared lock
across the two test functions (`conformance.rs:~28`) forces one-at-a-time
execution regardless of `--test-threads`.

The hypervisor is **not** the constraint: each `carrick run` is its own OS
process with its own HVF VM (confirmed). The constraints are shared mutable
state and a global kill.

## What breaks hermeticity (in priority order)

1. **Global `kill.sh` / `pkill -9 -f carrick` (THE blocker).** Between cases the
   harness force-kills wedged guests with a broad pattern (carrick renames
   argv0 to `carrick:`). Run two cases concurrently and one case's cleanup kills
   the OTHER's live carrick. *Enabler already present:* the harness spawns each
   probe with `.process_group(0)` (`conformance.rs:~452`), so each case has its
   own pgid. **Fix: replace the global pkill with a per-pgid `kill(-pgid)`
   scoped to that one case.** (The two wedged root `carrick trace` PIDs that
   needed interactive sudo to clear on 2026-05-29 are exactly the failure mode a
   global pkill papers over and a pgid-scoped kill avoids.)

2. **`--fs host` shared scratch.** The probe writes `/tmp/p` and creates files
   in the rootfs. If cases share one host rootfs/scratch dir, concurrent writes
   collide (same class as the `path2` `TempDir::drop → remove_dir_all` fork bug,
   see `project_path2_host_backend`). **Fix: a fresh ephemeral rootfs/scratch
   per case** (TempDir per probe, owner-pid-guarded Drop). Alternative:
   `run-elf` (empty per-process rootfs) — but that's the single-vCPU path and
   would stop exercising the threaded run-loop the gate currently covers.

3. **Timing sensitivity under load.** Async/threshold probes (io_uring — which
   flaked *serially* on 2026-05-29 — and anything with sleeps/deadlines) flake
   MORE under concurrent CPU contention (the ltp-conformance skill's standing
   warning). Unbounded parallelism trades wall-clock for false DIFFs.

Not a problem: the diff/compare is pure; the signed-binary build + image pull
are a legitimately-serial prefix done once before fan-out; the registry (:5050)
and Docker daemon handle concurrent read pulls / `docker run` fine (though the
LinuxKit VM is itself a soft serialization point under heavy concurrency).

## Design

- **Bounded fan-out**, not unbounded: a pool of `min(cores−2, ~6)`. Collapses
  ~130s → ~25s without saturating the Docker LinuxKit VM.
- **Per-case isolation**: own pgid (have it) + own TempDir rootfs (add) +
  per-pgid kill (swap out the global pkill).
- **Quarantine lane**: tag timing-sensitive probes (io_uring, sleep/deadline
  ones) and run THOSE serially, or with retry-on-DIFF; parallelize the rest.
  Cheaper than hardening every probe's waits.
- **Mechanism**: either `rayon`/bounded threads in `conformance.rs` (the diff is
  pure once #1+#2 are fixed), or the Workflow tool's `pipeline()` over the probe
  list (`run-carrick → run-docker → diff` per item; bounded concurrency + free
  progress UI + retry, without touching the harness).

## Sequencing

1. **Per-pgid kill first** — small, safe; turns "parallel corrupts other cases"
   into "parallel merely needs FS isolation."
2. **Per-case TempDir rootfs** — the FS isolation.
3. **Quarantine lane + bounded pool** — the actual parallelization + flake
   control.

## Verification for the change itself

Run the parallelized gate N times back-to-back; assert the verdict set is
identical to the serial run (no new DIFFs from races), and that timing-sensitive
probes don't flake more than their serial baseline. Confirm a wedged probe in
one case no longer kills siblings (inject a hang, verify only its pgid dies).
