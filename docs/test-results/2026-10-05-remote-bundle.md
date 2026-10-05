# Remote bundle review corrections, 2026-10-05

Portable tests ran on Linux x86_64 in `wt-remote-bundle`. No Docker,
remote acceptance gate, signed/HVF execution or load generator was used.
The remote CLI bindings run real Git, rsync and xtask preparation against
scratch directories; SSH is a local transport shim, and the acceptance
command is replaced with fixture preflight. They prove preparation and
receipt handling, not signed acceptance.

## Red-first observations

The following focused commands exited **101** before the corresponding fix.
The admission, gzip, provenance, attach-argument and inode tests ran with
tests added to the original PR implementation. Raw output is retained in
`/tmp/remote-bundle-*-red.log` on carrick-vm.

| Command | Observed false behavior |
| --- | --- |
| `cargo test -p carrick-xtask --test fixtures remote_preparation_rejects_unpublished_or_linked_archives -- --nocapture` | Symlink admitted; remote job exit `0` |
| `cargo test -p carrick-xtask --test fixtures fixture_verification_rejects -- --nocapture` | Four failures: truncated trailer, corrupt CRC, corrupt length, trailing garbage all verified |
| `cargo test -p carrick-xtask --test fixtures remote_preparation_persists_verified_provenance_for_both_sources -- --nocapture` | Run provenance file missing |
| `cargo test -p carrick-xtask --test fixture_cli remote_accept_rejects_bundle_arguments_on_attach -- --nocapture` | Conflicting attach path parsed successfully |
| `cargo test -p carrick-xtask --lib test_record_bundle_in_receipt -- --nocapture` | Reader and updated receipt had the same inode |
| `cargo test -p carrick-xtask --test fixtures remote_accept_cli -- --nocapture` | Malformed receipt annotation returned zero |
| `cargo test -p carrick-xtask --test fixtures remote_accept_cli_transfers -- --nocapture` | Attach dropped local-upload provenance: `Null` instead of the original entry |

Two additional controls exercised the old behavior at explicit boundaries:

- `cargo test -p carrick-xtask --test fixtures replacing_shared_archive -- --nocapture`
  exited 101 using the pre-fix archive verify/hash/restore sequence. Replacing
  A with a different valid bundle B for the same commit restored B's bytes.
  The final regression calls private capture at that boundary, replaces the
  shared source, and proves restoration and the recorded hash still name A.
- `cargo test -p carrick-xtask --test fixtures remote_preparation_provenance_write_failure -- --nocapture`
  exited 101 with `build_accept_job_script` temporarily restored from the
  original PR head. A directory blocking `fixture-bundle.json` publication
  was ignored and acceptance returned zero. The current script was restored
  immediately after the foreground command.

The worktree-reuse control
`cargo test -p carrick-xtask --test fixtures remote_accept_cli_transfers -- --nocapture`
then exited 101 before run-specific receipt storage was added: attach fetched
receipt timestamp `another-run` instead of `test`.

## Green coverage and limits

`cargo test -p carrick-xtask` passed with 162 normal tests and one existing
ignored subprocess helper (the helper is also invoked by its parent test).
The final suite covers symlink components, unfinished names, non-regular
sources, both bundle sources, gzip transport failures through CLI verification
and remote preparation, replacement after verification, failed provenance
publication, atomic receipt replacement, annotation failure, and attach after
an interrupted fetch and worktree receipt reuse.

`just clippy`, `cargo clippy -p carrick-xtask --all-targets -- -D warnings`,
and `just fmt-check` exited zero. `just lint-domains` must run on the clean
committed snapshot: its first dirty-tree attempt failed the compiler-capture
self-tests with `authoritative compiler capture requires clean tracked
snapshot inputs`. The final clean-tree result is recorded in the PR handoff.

The director owns the full host/signed acceptance gates. These portable
results confer no signed artifact receipt or macOS runtime acceptance.

## macOS temporary-root follow-up

The fixture test roots now use `std::fs::canonicalize` immediately after
creating each owned tempdir. Synthetic symlinks are created beneath that
physical root and remain unresolved. Admission continues to reject symlinks
in ancestors and in the final component; callers must supply physical
store paths, including `/private/var/...` instead of `/var/...` on macOS.

Cloudmac testing used a detached scratch worktree at
`/Volumes/carrick-build/wt/remote-bundle-portability-20261005-43f2d30-c`,
with `/Volumes/carrick/dev/env.sh` sourced. Since that environment overrides
TMPDIR, the tests explicitly used `getconf DARWIN_USER_TEMP_DIR`, which
returned `/var/folders/0f/31_g11zs5339g5sxg6hjmxgw0000gn/T/`.
Both runs were protected by `just lease carrick`. Fixture operations used
a separate scratch lock and cleared the inherited lease environment, so
they tested private gate admission without upgrading the outer host lease.

Before canonicalization, with specific rejection assertions added:

```sh
just lease carrick env -u CARRICK_HOST_LEASE_FD -u CARRICK_HOST_LEASE_MODE CARRICK_HOST_LEASE_PATH="$scratch/fixture-test.lock" TMPDIR="$mac_test_tmp" CARGO_TARGET_DIR="$scratch/target" cargo test -p carrick-xtask --test fixtures remote_preparation -- --nocapture
```

Exit **101**: all seven focused tests failed. Successful preparations hit
`Not a directory (os error 20)` at `/var`; rejection controls also failed
their intended-reason assertions instead of passing for that system alias.

After canonicalization, with `CARGO_TARGET_DIR="$scratch/target"` exported:

```sh
just lease carrick env -u CARRICK_HOST_LEASE_FD -u CARRICK_HOST_LEASE_MODE CARRICK_HOST_LEASE_PATH="$scratch/fixture-test.lock" TMPDIR="$mac_test_tmp" cargo test -p carrick-xtask
```

Exit **0**: 162 tests passed, one existing subprocess helper ignored. Linux
`cargo test -p carrick-xtask`, `just clippy`, xtask clippy with `-D warnings`,
and `just fmt-check` also exited zero. Symlink, publication-name,
non-regular-source, stale-SHA, gzip and provenance-write negatives now check
the intended rejection reason as well as failure.

The cloudmac fixture test source SHA-256 matched Linux:
`880c99b7c76e0302ecae70af44fe0a13ce0317e2e12b48527091697b501d1713`.
The scratch worktree and transfer files were removed after testing.
Logs are retained on carrick-vm under
`/tmp/remote-bundle-portability-{cloudmac-red,cloudmac-green,linux-tests,clippy,xtask-clippy,fmt}.log`.
These were VM-free macOS tests, not signed/HVF acceptance.

## Batch 6 rebase and combined fixture contracts

PR #54 was rebased onto `github/main` at
`b2e77e2ff2b9d1bdfe6d8d97f3ed7fbf4eb95fe2`. Prior commit authors and
trailers were preserved. Conflict resolutions and semantic reconciliation:

- `fixtures.rs` Verify combines `--bundle` and its manifest conflict with
  #43's `--receipt` and fresh `input_identity` evidence. The archive verifier
  now takes the receiver checkout and calls the existing `verify_bundle`
  after fully draining gzip. Exact HEAD, v2 schema, scoped dependency/source
  closure, recorded policy, controlled build environment, toolchain, ELF and
  executable inventory are checked before capture provenance is written.
- `accept.rs` retains #43's `fixture_validation` alongside `fixture_bundle`.
  Clean-checkout admission at entry, signed preflight and final receipt
  remains unchanged from main. Annotation and interrupted attach tests now
  carry real fixture-validation evidence and check that it survives.
- `lib.rs` keeps both the atomic publication helper and main's CI scaler.
  Atomic writes cover acceptance, installed, run-provenance and fresh
  verification receipts. Existing one-flush restore budgets still hold.
- Fixture scaffolding retains main's resolved local dependency graphs,
  default build policy, v2 schema, clean tracked workflow helper and all
  #43 regressions, plus canonical temporary roots and specific negative
  rejection reasons. Ancestor and final symlinks remain rejected.
- #6's lease supervisor and inherited socket/scope validation remain intact.
  Sandbox subprocesses clear all four inherited lease capability variables.
  Test-only no-op commands now use `true` from PATH: cloudmac has
  `/usr/bin/true` but no `/bin/true`.

Fresh red controls against the rebased implementation:

| Command | Exit | Observed failure |
| --- | --- | --- |
| `cargo test -p carrick-xtask --test fixtures archive_verification -- --nocapture` | 101 | All four new regressions failed: archive Verify admitted changed policy, scoped source and ambient override; verification overwrote the prior receipt inode |
| `cargo test -p carrick-xtask --test fixtures archive_verification_rejects -- --nocapture` | 101 | Prepare published run provenance before policy/ambient rejection during restore; source rejection assertion was then aligned with #43's `dirty fixture source inputs` |
| `cargo test -p carrick-xtask --test fixtures archive_verification_rejects_changed_scoped_inputs -- --nocapture` | 101 | Prepare left provenance behind despite invalid scoped inputs |

After the fix, `cargo test -p carrick-xtask --test fixtures archive_verification
-- --nocapture` exited **0**, all four tests passing. The rejected runs leave
neither provenance, verification evidence nor installed fixtures.

Cloudmac used `/Volumes/carrick-build/wt/remote-bundle-batch6-20261005-c`,
sourced `/Volumes/carrick/dev/env.sh`, and ran the full suite under
`just lease carrick`, with actual system `/var/folders` TMPDIR and a private
fixture-test lock. The child cleared `CARRICK_HOST_LEASE_FD`,
`CARRICK_HOST_LEASE_MODE`, `CARRICK_HOST_LEASE_SOCKET` and
`CARRICK_HOST_LEASE_SCOPE_FD`; the outer supervisor retained the host lease.

The first macOS suite exited **101**, with seven fixture failures naming the
missing `/bin/true`. Replacing only these test no-op paths fixed that issue.
Temporarily reverting root canonicalization then reran `remote_preparation`:
exit **101**, all seven focused tests failed at `/var`, including the specific
rejection assertions. A saved-file rename retained an older source timestamp,
so the immediate next full run reused the negative control's executable and
failed 17 tests. That result is not a green claim. Refreshing the restored
file's timestamp forced a recompile; the final complete suite exited **0**,
including all **54 fixture integration tests**. Its expected failing lease
helper is checked by a passing parent test. Three platform/subprocess helpers
remain ignored on macOS.

The four changed Rust source/test hashes matched Linux, including fixture
suite SHA-256:
`601f0b183e679341781d2e69f6693523d644080bbea266bd57699a9762fe6415`.
Cleanup exited **0** and printed `CLOUDMAC_SCRATCH_REMOVED`; the scratch
worktree and both transferred files were removed.

Logs on carrick-vm use `/tmp/remote-bundle-batch6-*`: `identity-red`,
`capture-red`, `source-red`, `identity-green`, `cloudmac-lease-red`,
`cloudmac-temp-red`, `cloudmac-green`, `cloudmac-cleanup`, `linux-tests`,
`linux-isolated-tests`, `clippy`, `xtask-clippy`, `fmt` and `domains`.
Final Linux check exit codes and the clean-snapshot lint result are recorded
in the PR handoff. No full acceptance, signed/HVF or Docker gate ran here.

Final Linux crate verification used
`CARRICK_HOST_LEASE_PATH=/tmp/remote-bundle-batch6-fixture-test.lock cargo test -p carrick-xtask`:
exit **0**, including all 54 fixture tests. The ordinary default-lock run was
blocked by another worktree's exclusive lint lease; after the isolated run
passed, only this task's blocked fixture process was stopped (SIGTERM),
leaving that worker and the live host lock intact. Linux xtask clippy,
`just clippy` and `just fmt-check` exited **0**. Clippy retains the existing
Linux configuration warning for the macOS-only `libc::proc_listallpids`
entry; it is not a new code warning.
