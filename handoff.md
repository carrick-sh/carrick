# Native Darwin Backend Handoff

Date: 2026-07-10

Branch: `codex/architecture-evidence-gates`

Implementation HEAD at handoff start: `311fae9e`
(`fix(native): virtualize private write-exec pages`)

Detailed local ledger: `.superpowers/sdd/progress.md` (git-ignored). This file
is the tracked continuation snapshot; the ledger contains the full campaign
history and attribution evidence.

## Active Goal

> Reach 100% conformance probes and more than 15% strict LTP parity on the
> native16k Darwin backend; communicate linux4k incompatibility to users; only
> block the goal if real workloads are found that require full linux4k
> compatibility.

The goal is unfinished and paused at this handoff. It is neither complete nor
blocked.

## Current Authority

| Surface | Confirmed result | Evidence |
| --- | ---: | --- |
| native16k musl probes | 355/374 PASS (94.9%), 19 gaps | `/tmp/carrick-native16k-probes-20260710-round5.log` |
| native16k GNU probes | 348/374 PASS, 26 report-only DIFFs | same round-5 log |
| strict clean LTP parity | 829/1492 (55.6%) | `/tmp/carrick-native16k-ltp-round1.jsonl` and `.log` |
| raw LTP differential parity | 1318/1492 (88.3%) | same LTP artifacts; do not use as the goal metric |

The strict LTP goal is met by a wide margin. The probe goal is not met.

`mprotectexec` passes the focused Linux differential test after `311fae9e`, so
the clean-lane projection is 356/374 with 18 remaining gaps. That number is not
authoritative until a full native16k probe campaign confirms it. Keep reporting
355/374 as the measured aggregate until then.

The user-facing page-profile contract is committed at `b9f0269c`. It prefers
`native16k`, describes `linux4k` as incomplete 4K-on-16K compatibility, and
states that unsupported native cases do not fall back to HVF.

## Latest Implementation

Commit `311fae9e` closes the ordinary private `mprotectexec` shape without
asking Darwin for a persistent writable-executable mapping:

- private, direct-arena, single-threaded native16k W+X pages alternate host
  protection between RX and RW on AArch64 permission faults;
- returning to execution restores translated syscall instructions and clears
  the instruction cache;
- multi-page protection changes roll back in reverse order, using sparse
  instruction undo records rather than full-page snapshots;
- partial `mprotect` splits VMA metadata and preserves shared/private
  provenance;
- backend protection failure is returned before dispatcher metadata commits;
- the probe now requires a clean child exit for executable-fetch success, so
  setup failures can no longer appear green.

The implementation deliberately returns `EOPNOTSUPP` and records partial
syscall evidence for shapes whose invariants are not yet supportable:

- shared W+X mappings;
- high/alias W+X mappings;
- executable `mprotect` with sibling guest threads;
- creating a clone thread after W+X state exists;
- `vfork` while W+X state exists.

Same-16K-host-page self-modification while executing from that page remains
explicitly unsupported at the fault boundary.

Ordinary `fork` remains supported because private mappings inherit through host
COW. These limits are correctness boundaries, not candidates for silent
permission widening.

Fresh verification on the exact commit candidate:

- `cargo test -p carrick-runtime --lib`: 625 passed, 0 failed;
- targeted runtime/CLI clippy with `-D warnings`: clean;
- `just lint-domains`, `just fmt-check`, and `git diff --check`: clean;
- `just build`: release binary rebuilt and signed;
- `codesign --verify --verbose=2 target/release/carrick`: valid;
- `native16k_mprotect_exec_permissions_match_linux`: passed;
- direct signed native16k output: all five permission invariants true, with
  statuses `139,0,139,0,0`;
- fresh signed live stress: 20/20 passed.

The full probe campaign, full `just ci`, and fork benchmark were not rerun after
this commit. Do not imply otherwise.

## First Next Action: Fork Benchmark

Measure the payoff before doing more conformance work. No native-backend fork
number has been established yet.

### Harness preparation

`bench-native/Cargo.toml` currently exposes `perf_fork_exec`, but not
`perf_fork` or `perf_fork_scale`. Add both bins, pointing at the existing probe
sources, and commit that harness-only change separately. Do not alter the probe
algorithms while establishing the first baseline.

Build the exact-source Linux and Darwin binaries:

```sh
./scripts/build-probes.sh --native-pie
cargo build --release --manifest-path bench-native/Cargo.toml \
  --bin perf_fork --bin perf_fork_exec --bin perf_fork_scale
just build
```

### Lanes

Run lanes serially. Never overlap a Carrick lane with Docker.

1. native16k, using the native PIE Linux binary with `run-elf`;
2. HVF, using the same Linux binary and default backend;
3. native arm64 Docker Linux, using the same Linux binary;
4. host Darwin, using the `bench-native` binary built from the same source.

Measure at least `perf_fork` and `perf_fork_exec`. Run 3-5 complete repetitions
per lane after warm-up and retain every raw log. Then run one diagnostic
`perf_fork_scale` matrix, starting with `(threads=0, mem=0)`,
`(threads=0, mem=256)`, and `(threads=4, mem=0)`. Treat a native threaded-lane
rejection or failure as evidence, not as a reason to omit the point.

Representative Carrick invocations:

```sh
CARRICK_RUN_ID=native-fork-<rep> timeout 180 \
  target/release/carrick run-elf --raw \
  --exec-backend native --native-page-profile native16k \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork

CARRICK_RUN_ID=hvf-fork-<rep> timeout 180 \
  target/release/carrick run-elf --raw \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork
```

Use the corresponding `perf_fork_exec` path for spawn measurements. For Docker,
use the established base64 injection transport so the timing probe itself is
identical and injection occurs before its internal measurement loop. Run the
host binaries directly from `bench-native/target/release/`.

Acceptance gates from the approved design:

- native `perf_fork` p50 <= 2x host Darwin p50;
- native `perf_fork` p95 <= 3x host Darwin p95;
- native `perf_fork_exec` materially beats warmed HVF.

Report absolute p50/p95 values and native/host, native/HVF, and native/Docker
ratios. Do not retrofit a numeric definition of "materially" after seeing the
result.

Historical references only, not current baselines:

- recent HVF `perf_fork` p50 was roughly 2.06-2.14 ms;
- recent HVF `perf_fork_exec` p50 was roughly 7.23-7.98 ms;
- the 2026-07-08 host Darwin `fork_exec` p50 was 1607.875 us;
- the corresponding Docker `fork_exec` p50 was 82.833 us.

Record host model, macOS version, git SHA, backend/page profile, run ID, probe
hash, p50, p95, minimum, and iteration count. Audit for leftover Carrick,
Docker, and `yes` processes after every lane. Use scoped run IDs and
`scripts/sudo/kill.sh <run-id>`; never use a broad `pkill`.

## Remaining Probe Work

Assuming the aggregate lane confirms `mprotectexec`, the projected 18 gaps are:

```text
accounting
childsubreaper
clone3args
execthreads
forkfpreclaim
getrandomvdso
getrandomvdsofork
getrandomvdsoloop
itimer
keydeny
ltpcheckpointexec
memmap
pidnsroot
sigchld
sigwaitalarm
sysvsem
vdsosymbols
waitidcputime
```

After the fork benchmark, rerun the full native16k lane to promote
`mprotectexec` from projection to authority. Then work deterministic clusters:

1. native vDSO: `getrandomvdso*` and `vdsosymbols`;
2. guest CPU-time/accounting: `accounting`, `itimer`, `waitidcputime`;
3. lifecycle: `childsubreaper`, `clone3args`, `execthreads`,
   `forkfpreclaim`, `ltpcheckpointexec`, and `sigchld`;
4. transport/namespace/signal/SysV residuals.

`keydeny` is a Docker default-seccomp policy mismatch. Linux keyring syscalls
are available to unprivileged processes outside that policy. Do not make absent
Carrick keyring handlers return `EPERM` just to match Docker; close it through a
container policy layer or a real keyring implementation.

## Aggregate Recheck

```sh
./scripts/build-probes.sh --native-pie
just build
set -o pipefail
CARRICK_EXEC_BACKEND=native \
CARRICK_NATIVE_PAGE_PROFILE=native16k \
CARRICK_RUN_ID=native16k-probes-round6 \
cargo test -p carrick-cli --test conformance conformance_probes \
  -- --nocapture 2>&1 | \
  tee /tmp/carrick-native16k-probes-20260710-round6.log
```

The test can remain nonzero while named probe gaps exist; classify the complete
PASS/FAIL list and distinguish that expected final assertion from a crash or
incomplete campaign. Keep Carrick and live Docker phases disjoint and verify
process residue at phase boundaries.

Before claiming the goal complete, require all of:

- measured 374/374 native16k musl probes;
- strict clean LTP parity still above 15%;
- the approved linux4k compatibility statement remains accurate;
- `just ci` passes;
- a signed live native16k workload demonstrates the backend end to end;
- tracked tree is clean and each change is in a narrow logical commit.

## Debugging Constraints

- Read `.agents/skills/carrick-native-debug/SKILL.md` before native fault or
  lifecycle triage.
- Use `carrick debug lldb-run` or the native fatal record for hangs/faults;
  compare the relevant lifecycle contract with HVF before changing behavior.
- Build and run with `just build`; plain `cargo build` is not a runnable gate.
- Preserve Apple `ld64` and verify signing. Do not use `lld` for Carrick.
- Do not read Linux kernel or other GPL source. Use specifications, man pages,
  and differential Linux observation.
- Keep commits logical and update `.superpowers/sdd/progress.md` after each
  measured result or architectural decision.
