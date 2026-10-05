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
