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
