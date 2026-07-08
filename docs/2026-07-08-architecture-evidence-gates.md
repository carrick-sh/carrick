# Architecture evidence gates: E1 fork floor and arena coherence

Date: 2026-07-08

This records the first evidence-gathering phase from
`docs/superpowers/specs/2026-07-08-carrick-architecture-strategy-memo.md`.

## Decision

Continue Carrick on the process-native "arena plus leased VMM residency" path,
but do not pursue the HVF parent-keeps-VM fork variant.

The E1 probe is refuted on current Hypervisor.framework behavior: a fork child
cannot clear the inherited HVF state and create its own VM while the parent keeps
its VM live. The parent remains unperturbed, so the failure is not child-side
destruction corrupting the parent; the child simply remains blocked at
`hv_vm_create`.

The process-section arena migration is implementation-complete for the current
scope: run-state, child metadata, PID namespace membership, wait metadata,
pre-fork child registration, exhaustion behavior, and supervisor cleanup now
share generation-stamped arena records without a hot-path daemon.

## E1 fork-floor evidence

Fresh current-tree run:

- Build: `just build -p carrick-vmm-hvf --bin hvf_fork_probe`
  - Result: release build succeeded; wrapper re-signed `target/release/carrick`.
- Probe signing:
  `codesign --force --sign - --entitlements scripts/entitlements.plist target/release/hvf_fork_probe`
  - Result: succeeded.
- Probe:
  `target/release/hvf_fork_probe parent-keeps-vm 50 | tee target/conformance/logs/hvf-probes/parent-keeps-vm-20260707-185502.log`
  - Result: all 50 iterations refuted E1.
  - Child: `rc_direct=HV_BUSY(0xfae94002)`,
    `rc_destroy=HV_NO_DEVICE(0xfae94006)`,
    `rc_create=HV_BUSY(0xfae94002)`,
    `child_code=2`.
  - Parent: every verdict line had `pre_ok=true`, `post_ok=true`,
    `exit_match=true`, and `parent_destroy=(HV_SUCCESS,HV_SUCCESS)`.
  - Summary: `parent-keeps-vm failures=50`.
- Exit contract check:
  `bash -o pipefail -c 'target/release/hvf_fork_probe parent-keeps-vm 1 >/tmp/carrick-e1-exit-check.log'`
  - Result: `probe_exit=1`, as expected for the refuted path.

Verdict: **E1 REFUTED**. Skip the threaded E1 variant and skip the
`CARRICK_HVF_FORK_PARENT_KEEPS_VM` engine path. The next fork-floor track is E2:
lazy stage-2 replay and mapping coalescing to shrink the parent/child rebuild
cost that remains unavoidable under HVF.

## Arena/process-section reconciliation

Reconciled against:

- `docs/superpowers/plans/2026-07-07-carrick-kernel-arena-foundation.md`
- `docs/superpowers/plans/2026-07-07-arena-process-section.md`

Current implementation state:

- `carrick-kernel` exists with typed domains, `WaitWake`, robust bucket locks,
  file-backed `KernelArena`, `ArenaLayout`, `PermitSection`, `ProcessSection`,
  and `ArenaError`.
- `ArenaLayout` is versioned at `ARENA_VERSION = 2` and contains both
  `permits` and `processes`.
- HVF vCPU admission uses the arena permit section; the existing reaper remains
  the stale-owner cleanup path.
- `ProcessSection` has 4096 generation-stamped records with claim-sentinel
  publication and loud exhaustion.
- Runtime run-state publication adopts the process's existing record instead of
  allocating duplicate run-state records.
- The host child table and PID namespace membership live on the process section.
- Fork registration is parent-prefilled before `fork(2)`; the child only
  publishes its own liveness. The post-fork self-registration repair paths are
  gone.
- Follow-up defects from the B6/B7 review are fixed:
  - wait-any park keeps `-1` for direct children;
  - parent publishes the pre-fork child record by ref, not through a clobberable
    process-global stash;
  - run-state records no longer duplicate/leak process records;
  - member record reuse clears stale wait state;
  - fork-time process-record exhaustion degrades to guest `EAGAIN`;
  - supervisor sweep releases dead-owner records whose exits no live guest can
    still consume;
  - supervisor exit-watch rearming is keyed by `(host pid, generation)`.

One verification bug was found in this run: the default parallel
`cargo test -p carrick-kernel --lib` hung in `arena_is_visible_across_fork`
because the fork child called `std::process::exit(0)` inside the multithreaded
Rust test harness. The child now uses `libc::_exit(0)`, matching the other
fork tests' post-fork discipline.

## Verification

Commands run in this phase:

- `cargo test -p carrick-kernel --lib`
  - Result before the `_exit` fix: hung in `arena_is_visible_across_fork`.
  - Result after the fix: 17 passed.
- `cargo test -p carrick-kernel --test prefork_registration -- --test-threads=1`
  - Result: 2 passed.
- `cargo test -p carrick-host --lib -- --test-threads=1`
  - Result: 39 passed.
- `cargo test -p carrick-runtime run_state --lib -- --test-threads=1`
  - Result: 10 passed.
- `cargo test -p carrick-runtime namespace::pid --lib -- --test-threads=1`
  - Result: 9 passed.
- `cargo test -p carrick-runtime setpgid_tests --lib -- --test-threads=1`
  - Result: 1 passed.
- `cargo test -p carrick-vmm-hvf permit_table_is_the_arena --lib -- --test-threads=1`
  - Result: 1 passed.
- `just build -p carrick-cli -p carrick-conformance`
  - Result: release build succeeded; `target/release/carrick` was signed.
- `target/release/carrick-conformance --workers 1 --no-image-refresh --suite ltp-ptrace06 --suite ltp-clone08 --suite ltp-kill10 --suite ltp-waitpid06 --suite ltp-waitpid08 --suite ltp-waitpid10 --jsonl target/conformance/architecture-evidence-process-section-20260707-185842.jsonl`
  - Result: 6 Carrick runs, 0 Docker runs, 6 cached oracles, all MATCH:
    `ltp-clone08`, `ltp-kill10`, `ltp-ptrace06`, `ltp-waitpid06`,
    `ltp-waitpid08`, `ltp-waitpid10`.
- `cargo clippy -p carrick-kernel --all-targets -- -D warnings`
  - Result: passed.

Existing committed diary evidence remains relevant:

- E1 original verdict: `docs/2026-07-07-conformance-bless-diary.md`, lines
  242-264.
- Arena foundation landing: same diary, lines 1505-1567.
- Process-section B7 measurement and policy follow-up: same diary, lines
  1568-1675.
- B6/B7 review findings and fixes: same diary, lines 1677-1737.

## Next track

1. Fork floor: write and execute the E2 lazy-replay plan. Instrument
   `fork_rebuild` so the next change is measured by mapping count, replay time,
   and `perf_fork`/process-spawn deltas. Keep the one-Linux-process-to-one-host-
   process invariant; do not add a broker on fork.
2. Arena: proceed to explicit lease classes and cold death sweep:
   `InitialExec`, `ForkChildBootstrap`, `CloneThreadRun`, `ExecveRebuild`, and
   `WakeFromBlockingSyscall`. Normal release and hard-death reclaim must be
   generation-checked and idempotent.
3. Shared Linux objects: after lease classes, move process-shared futex requeue
   and SysV IPC into arena sections one object class at a time. Hot block/wake
   paths stay atomics plus host futex primitives, never supervisor RPC.
