# Conformance Oracle Capabilities Review (ORACLE-CAPS-1)

## Summary

Native-arm64 Docker evidence demonstrates that two LTP suite declaration errors in the conformance manifest (`scripts/conformance/suites.toml` and `crates/carrick-conformance/src/generate.rs`) resulted in under-privileged oracle failures:
1. `ltp-syslog12`: Missing `CAP_SYSLOG` caused kernel parameter validation in `do_syslog()` to be bypassed in favor of early `EPERM` rejections, failing 5 of 6 assertions.
2. `ltp-semctl06`: Missing `CAP_IPC_OWNER` caused cross-UID/mode `semop()` calls to fail with `EACCES` (errno 13).

Both suites succeed with exact least-privilege capability grants (`--cap-add SYSLOG` and `--cap-add IPC_OWNER`). These direct transcripts supersede historical claims that privileged `semctl06` still fails.

## Evidence Analysis

Evidence directory: `/Volumes/CaseSensitive/carrick/target/conformance/fix-forward-20260909/oracle-feature-review/`
- **Image**: `localhost:5050/ltp:arm64` (`sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`), kernel `7.0.12-linuxkit #1 SMP PREEMPT Thu Aug 27 14:02:21 UTC 2026 aarch64`, LTP release `20260529`.

### 1. `ltp-syslog12`
- **Default capabilities** (`results.json`, `syslog12.err`):
  - Exit code: 1
  - Outcome: 1 passed, 5 failed (`TFAIL: syslog() with invalid type/command expected EINVAL: EPERM (1)`, `NULL buffer`, `negative length`, `console level < 0`, `console level > 8`).
  - Mechanism: Linux `do_syslog()` enforces privilege checks via `check_syslog_permissions()` before checking parameter validity. Without `CAP_SYSLOG`, parameter validation is never reached.
- **With `--cap-add SYSLOG`** (`cap-results.json`, `syslog12-cap.err`):
  - Exit code: 0
  - Outcome: 6 passed, 0 failed (5 `EINVAL` assertions for invalid arguments + 1 `EPERM` assertion for dropped non-root user).

### 2. `ltp-semctl06`
- **Default capabilities** (`results.json`, `semctl06.out`):
  - Exit code: 1
  - Outcome: `TFAIL: semctl06.c:181: first semop() failed errno 13` (EACCES) across 3 subtests, test failed exit 0x100.
  - Mechanism: Linux SysV semaphore permissions (`ipcperms()`) require `CAP_IPC_OWNER` when operating on a semaphore set where neither the caller UID nor creator UID matches the permission set.
- **With `--cap-add IPC_OWNER`** (`cap-results.json`, `semctl06-cap.out`):
  - Exit code: 0
  - Outcome: `TPASS: semctl06 ran successfully!`.

## Least-Privilege & Scope Control

- **Exact least grants**:
  - `ltp-semctl06` granted `--cap-add IPC_OWNER`.
  - `ltp-syslog12` granted `--cap-add SYSLOG`.
- **No broad grants**: Neither suite receives `--privileged` or `--security-opt seccomp=unconfined`.
- **No known gaps added/modified**: Neither suite carries a `known_gap` (both are expected to test valid behavior).
- **Exact scope preservation**:
  - Total unique suites remains exactly 2,127.
  - Exactly 2 rows changed in `scripts/conformance/suites.toml` and `DOCKER_FLAG_OVERRIDES` in `generate.rs`.
  - Image (`localhost:5050/ltp:arm64`), command, timeout (40s), tier (`full`), verdict (`ltp`), and weight (`light`) are preserved without drift.
  - Sibling suites (`ltp-semctl01..05,07..09`, `ltp-syslog11`) remain unprivileged.

## Carrick Capability Policy & Flag Mirroring

The conformance generator (`crates/carrick-conformance/src/generate.rs::carrick_flags_for`) automatically extracts all `--cap-add <CAP>` entries from `docker_flag_overrides` and mirrors them onto `carrick_flags`:
```rust
carrick_flags = ["--fs", "host", "--cap-add", "<CAP>"]
docker_flags = ["--cap-add", "<CAP>"]
```
This preserves the symmetric execution contract: both Carrick and the Docker oracle are evaluated under the exact same capability constraints, preventing false Carrick gap attributions caused by container privilege asymmetry.

## Verification Evidence

1. **Focused Host Test**:
   - `semctl06_and_syslog12_oracle_capabilities_are_exact_and_mirrored` added to `crates/carrick-conformance/src/generate.rs`.
   - **Red proof**: Captured in `target/oracle-caps-review/test-red.txt` (assertion failure `left: None, right: Some(["--cap-add", "IPC_OWNER"])`).
   - **Green proof**: Captured in `target/oracle-caps-review/test-green.txt` (194 passed, 0 failed).
2. **Independent Inventory Diff**:
   - Captured in `target/oracle-caps-review/inventory-diff.txt` verifying 2,127 total/unique suites and exactly 2 changed rows.
3. **Clippy and Formatting**:
   - `RUSTC_WRAPPER= cargo clippy -p carrick-conformance --all-targets -- -D warnings` (exit 0).
   - `cargo fmt --all -- --check` (exit 0).

## Pending Steps

Codex owns oracle policy, acceptance, and re-blessing. Codex will refresh only the proved native-arm64 oracle declarations serially and independently rerun signed gates after review. Passing host tests confirm declaration and generator consistency but do not close the oracle family.
