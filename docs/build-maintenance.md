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
just worktree-gc --apply  # remove eligible managed worktrees
just worktree-run bash   # hold admission for a foreground worker session
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

Repo Cargo recipes and the direct signed entry points acquire a shared Rust
`worktree-run` lifetime guard. Signed entry points retain it through linking,
signing, tests and scoped EXIT cleanup. Each Git worktree administrative
directory atomically records a random checkout-generation token authenticated
with the root device/inode. The persistent authority is keyed by that token
under the Git common directory, outside removable checkouts. Replacing a
checkout, even with a reused directory inode, cannot inherit its old live
authority or retirement tombstone. GC only considers managed checkouts, claims their exclusive guard
without waiting, and holds it through deletion. Active admission keeps the
checkout; a retirement tombstone rejects waiting commands after removal.
Unmanaged checkouts are reported and preserved.

Apply also acquires existing native Cargo target locks and rechecks HEAD,
cleanliness and root-visible process use immediately before deletion. Only
the exact native Cargo lock descriptors owned by GC are exempted from that
census; unrelated descriptors and cwd stay visible, including GC's own.
Apply adds owner read/write/search permission to directories (including read-only
census directories), and uses `git worktree remove` without force. Symlinks are
refused at the supplied checkout root and at registered roots; a registered
root must equal its canonical path. These checks run before permission changes
and again before removal. Git can partially delete a checkout before returning
an error, so any attempted removal keeps its retirement tombstone even on
failure. Inspect/recover such a checkout before explicitly re-enrolling a new
Git worktree generation. Git also refuses dirty or newly locked worktrees. Branch refs
are retained. This authority covers foreground repo entry points and explicit
`just worktree-run` sessions. Arbitrary processes and external worker launchers
do not participate; root lsof still checks them, but its census cannot
exclude a new arbitrary launch. The command does not claim arbitrary-launch
safety. Keep such worker sessions under `worktree-run` or a Git worktree lock.
The separate worker launcher is unchanged. Cleanup is dry-run by default;
automation must explicitly pass `--apply`.

## Persistent target cleanup

```sh
just worktree-gc --prune-targets                 # dry-run; default age 2 days
just worktree-gc --prune-targets --days 3 --apply
just worktree-gc --prune-targets --target-dir /Volumes/carrick/dev/gate-worktree/target --apply
```

This mode keeps every checkout and prunes only entries beneath
`target/{debug,release}/{deps,build,.fingerprint}`. An entry and all its
descendants must meet the age threshold. Recent or future timestamps,
symlinks and hardlinked files are kept. Signed binaries, receipts and other
target subdirectories are preserved. Cargo rebuilds removed intermediates.
The output reports allocated bytes reclaimed (or eligible during dry-run).

Before scanning, the command atomically claims the dev directory's
`gate-worktree.lock`, then tries an exclusive host lease without waiting.
If either lock is held, it skips without deleting anything. It retains both
guards through removal. Before any census or deletion it also holds exclusive
locks on Cargo's native `target/{debug,release}/.cargo-lock` files. Ordinary
Cargo builds participate in these locks even when bypassing the host lease.
These lock files are never pruned. Their descriptors are explicitly inherited
by the deletion shell and utilities, so killing the Perl parent cannot release
exclusion while a deletion child remains alive. The local and remote host
lease descriptors also follow deletion children. Root-visible lsof exempts
only the two exact exclusively held Cargo lock paths; every artifact stays
visible even when opened by a guardian process.
All accounting utilities are checked before scanning; failed or invalid byte
accounting stops before unlinking the candidate. It uses the same root-visible
lsof checks as worktree cleanup. Run from another checkout when pruning a target containing the
running xtask executable: its mapping correctly makes that target busy.

When remote-accept sees less than 40 GiB free, it logs an idle-only pruning
attempt before refusing. The client's Rust code sends the same find-based
pruning body over SSH, targeting `gate-worktree/target` with the default
two-day threshold, then checks free space again. No remote checkout or build
is needed. macOS has no `flock(1)`; its stock `/usr/bin/perl` holds the existing
host lease with `LOCK_EX|LOCK_NB` while the generated command runs. The remote
wrapper claims the checkout lock first and honors `CARRICK_HOST_LEASE_PATH`
from the host's `env.sh`, just as local pruning does. A busy lock, missing
utility (including Perl), or insufficient reclaimed space preserves the
existing refusal; the 40 GiB gate requirement is unchanged.
