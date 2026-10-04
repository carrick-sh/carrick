# Build caches and worktree maintenance

All `just` recipes and direct `scripts/build-signed.sh` and
`scripts/test-signed.sh` invocations load `scripts/lib/build-env.sh`.
Builds use sccache through `RUSTC_WRAPPER` by default. Install it per user:

```sh
cargo install sccache --locked --root "$HOME/.cargo"
just build-cache
CARRICK_SCCACHE=0 just build
```

Only the exact value `0` disables caching (and clears `RUSTC_WRAPPER`).
An explicitly supplied nonempty `RUSTC_WRAPPER` is respected when enabled.
A missing sccache executable fails the build; install it or use the hatch.
Hosted and trusted-hardware CI install it per user after restoring Rust caches.
No linker, Rust flags, entitlement, DOF processing, or signing steps change:
macOS still uses Apple ld64 and the existing post-link signing path.

| Host | Default `SCCACHE_DIR` | Default `SCCACHE_CACHE_SIZE` |
|---|---|---|
| carrick-vm | `~/dev/.sccache` | `10G` |
| cloudmac | `/Volumes/carrick/dev/.sccache` | `10G` |
| director Mac | `/Volumes/CaseSensitive/carrick/.sccache` | `10G` |

Both variables can be overridden in the host environment (`env.sh` on cloudmac).
The volume defaults are selected by directory presence, preferring cloudmac's
volume when both exist. Restart your own idle sccache server after changing its
storage configuration; a running server retains its previous configuration.
`just build-cache` reports the effective server location, cap, hits and misses.
Do not stop a server while other workers are building.

sccache reuses compiler outputs; it does not share or eliminate Cargo target
directories, cache binary links, or guarantee every crate is cacheable.
Source paths, generated inputs and compiler configuration can reduce reuse
across worktrees. Each worktree still owns its targets and signed artifacts;
remove landed worktrees to reclaim those outputs.

## Worktree cleanup

```sh
just worktree-gc          # census only; never deletes
just worktree-gc --apply  # remove eligible worktrees
```

The census prints size (allocated disk usage), branch, dirty state, landing
proof, process-use state and action. `git cherry main HEAD` must report no
unmatched patches, and unique merge commits must be absent (cherry omits
merges and cannot prove their conflict resolutions). Alternatively, both
`git cherry main land/STACK` and `git cherry land/STACK HEAD` must meet those
conditions. A `land/*` branch name alone never proves landing. Squashed changes
that cannot be proven patch-equivalent are kept. Main and stack refs are local;
fetch/update them before running the census if they are stale.

Main checkout, the invoking checkout, branches named main, locked worktrees,
and paths containing `gate-worktree` or `gate-worktrees` are always protected.
Tracked changes and untracked files both make a worktree dirty; ignored build
outputs can be reclaimed. `lsof +D` checks cwd, open files and executable
mappings throughout the target tree. The census needs root visibility so an
empty result cannot hide another user's processes. Ordinary invocations use `sudo -n -u root` for lsof only;
removal retains the invoking user's permissions. Missing lsof, denied sudo,
warnings or an ambiguous exit status keep the worktree without prompting.
Install lsof in your user PATH if needed. `Busy` or `Unknown` never permits
deletion.

Apply rechecks HEAD, cleanliness and process use immediately before deletion,
adds owner read/write/search permission to directories (including read-only
census directories), and uses `git worktree remove` without force. Symlinks are
not traversed. Git also refuses dirty or newly locked worktrees. Branch refs
are retained. Quiesce worktree creation/build launches during apply: neither
Git nor lsof provides an atomic exclusion against a process starting after
the final check. The command is deliberately dry-run by default; automation
must explicitly pass `--apply`.
