# Task 7 Report: Run All Probes And Record Evidence

## Scope

- Implemented Task 7 only.
- Kept changes in the excluded `bench-native` crate and docs.
- Did not touch `carrick-runtime`, HVF, HAL, backend selection, or Task 8 scope.

## Files Changed

- `bench-native/src/native_exec_probe/mod.rs`
- `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`
- `.superpowers/sdd/task-7-report.md`

## Implementation

- Replaced the `run_all()` stub in `bench-native/src/native_exec_probe/mod.rs`.
- Wired `all` to run the six existing probes in plan order:
  `page-size`, `fixed-map`, `execmem`, `brk-trap`, `branch-gateway`,
  `fault-discriminator`.
- Preserved per-probe output by printing every probe report before deciding the
  overall exit status.
- Returned an error after printing when any required probe reported
  `status=fail`, so `native_exec_probe all` exits non-zero while still emitting
  all six probe lines.

## Verification

### Red

Command:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

Observed before the change:

```text
native_exec_probe: all probe is implemented after the individual probes exist
```

Exit status: `2`

### Green

Command:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

Captured exact stdout:

```text
probe=page-size status=fail host_page_size=16384 linux_guest_page_size=4096
probe=fixed-map status=pass addr=0x700000000000 len=16384 child_exit=0
probe=execmem status=pass mode=rw-to-rx return=42
probe=brk-trap status=pass child_exit=0
probe=branch-gateway status=pass return=77 branch_word=0x14000010
probe=fault-discriminator status=pass guest_fault_exit=90 host_fault_exit=91
```

Captured stderr:

```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.00s
Running `bench-native/target/debug/native_exec_probe all`
native_exec_probe: native execution feasibility probe failed
```

Exit status: `2`

Interpretation:

- Non-zero exit is expected for this host because `page-size` is a required
  gate and reported `status=fail`.
- The remaining five probes reported `status=pass`.

### Formatting

Command:

```sh
cargo fmt --manifest-path bench-native/Cargo.toml
```

## Evidence Doc

- Wrote `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`.
- Included only the exact probe stdout lines in the `Output` section.
- Recorded `verdict: blocked` because the first required gate, `page-size`,
  failed on a 16K-page Darwin host.

## Commit

- Commit created: `test(bench-native): wire native feasibility probe sweep`
- The final hash is intentionally omitted here because amending the report would
  change it again; use `git rev-parse --short HEAD` from this commit if the
  exact identifier is needed.
