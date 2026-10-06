# N1 file-backed mmap paused handoff

N1 was paused by the owner on 2026-10-05 so x86 can settle the shared core
first. This branch preserves a VM-free red/green candidate fix; it has not had
the final signed or landing gates and must be rebased once onto that settled
core.

## Fix inventory

- `af7bda476` — **kept** in integrated tip `56bf8c0ca`: typed exit-participant
  revision custody.
- `975ce28fc`, `14649f563`, `246038022` — **ported/kept** by merge commit
  `56bf8c0ca`: x86 order 4 wait/lifecycle core ownership and its review fixes.
- This branch's file-backed mmap commit — **in progress**: a typed
  owner-reserved content-write path fixes the pre-existing N1 regression from
  `274b8a533`, while retaining the existing privileged COW and translated-write
  enforcement. No moved carrick-core reservation defect was found.
- The four n1-cm fixes dropped during its rebase — **not handled here**; their
  owner is porting them independently.

## Evidence and open failures

- Director acceptance logs for exact tip `56bf8c0ca` are under
  `/Volumes/CaseSensitive/carrick/.worktrees/gate-n1-local/target/el1-gate/56bf8c0ca/`.
  `el1-embed.log` contains the two-live-process file-map ENOMEM, and
  `probe-cases.log` contains the inotify/Python loader ENOMEM.
- Exact signed red run `n1-filemap-red3-20261005` reproduced
  `copyout_failed reuse-file-map ret=-12`; scoped cleanup reported zero
  processes. Diagnostic runs localized it to mmap's file-content copy, where
  the ordinary owner user-transfer portal rejected the opaque reserved venue.
- VM-free witness
  `delegated_fixed_file_map_reuses_a_retired_el1_reservation` failed with
  `LinuxErrno(12)` when the typed owner-reserved write selection was removed,
  then passed after restoration.
- The final focused signed green was cancelled before host-lease admission when
  the owner paused N1 and prohibited further signed cycles. Consequently the
  exact signed copyout test, `case_inotify_watch_churn`, `just ci`, and loom are
  still open for this candidate.
- The compound-IPA exact-inventory failures remain owned by n1-cm; examples are
  in `generic-probe-shards.log` and `fresh-executable-page.log` in the same
  director evidence directory.

## Next step

After rebasing once onto the settled shared core, resolve this narrow typed
seam against the final core reservation API, rerun the VM-free witness, then
run the exact signed copyout test and focused inotify churn witness. If those
are green, complete `just ci` and the justfile loom recipe before promoting the
fix from WIP.
