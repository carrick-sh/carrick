# Build caches and worktree maintenance

All `just` recipes and direct `scripts/build-signed.sh` and
`scripts/test-signed.sh` invocations load `scripts/lib/build-env.sh`.
Builds use sccache through Cargo's `--config build.rustc-wrapper` by default.
Install it per user:

```sh
cargo install sccache --locked --root "$HOME/.cargo"
just build-cache
CARRICK_SCCACHE=0 just build
```

Only the exact value `0` disables automatic caching. An explicitly supplied
`RUSTC_WRAPPER` retains Cargo's normal precedence, including with cache opt-out.
The automatic wrapper is a Cargo option, so it does not enter test or fixture
admission environments. Explicit ambient wrappers still fail fixture policy;
controlled fixture builds retain their declared environment and configuration.
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
signing, tests and scoped EXIT cleanup. `worktree-run` replaces itself with the
command, preserving its PID and exact exit/signal status. Only the checkout
guard is inherited through exec, so the existing lease supervisor observes
public runner death and retains admission through cancellation and reaping;
the host lease descriptor remains exclusive to that supervisor.
Each Git worktree administrative
directory atomically records a random checkout-generation token authenticated
with the root device/inode. The persistent authority is keyed by that token
under the Git common directory, outside removable checkouts. Replacing a
checkout, even with a reused directory inode, cannot inherit its old live
authority or retirement tombstone. GC only considers managed checkouts, claims their exclusive guard
without waiting, and holds it through deletion. Active admission keeps the
checkout; a retirement tombstone rejects waiting commands after removal.
Unmanaged checkouts are reported and preserved.

Admission, retirement, host lease and native Cargo lock descriptions open with
CLOEXEC. Their owning process explicitly unlocks before closing, so unrelated
forks still waiting to exec cannot extend a released hold. Dropping an inherited
guard in a fork child only closes its copy; it cannot unlock the parent's live
authority. Only the named checkout exec handoff and scoped lifetime writers are
made inheritable, and supervisor-side writer copies close immediately after
spawn. The host flock descriptor is never handed to workloads.

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
Pruning resolves the target once and authenticates its device/inode, including
through symlinked worktree ancestors. A Rust pass retains that directory handle,
opens profiles, locks and every candidate descendant with `openat(O_NOFOLLOW)`,
and measures age and allocated bytes from those retained objects. Traversal and
deletion use directory-relative operations; display paths never authorize
unlinking. Replacing or renaming the target after the final identity check cannot
redirect deletion into its replacement. Native Cargo and host leases live in
the same process that deletes; there is no shell/Perl deletion child.

Root-visible `lsof -F pfn` validates complete process/descriptor/name records.
Only exact owned descriptors with authenticated display names are exempt, and
every retained object in the queried subtree must appear. A namespace change
during the census cannot turn an empty result into proof of idle. Unrelated
descriptors, cwd/mappings, warnings, malformed/duplicate records and missing
objects keep the target. Before unlinking, an eligible candidate is atomically
moved into a private `.carrick-prune-<token>` directory under the held root and
its retained tree is verified again. Changed candidates are preserved there
for recovery rather than deleted. Inspect these directories after interrupted
or failed pruning; they are excluded from normal artifact cleanup. Owner
permissions needed for removal are added through held directory handles only.

Age and byte accounting are native Rust operations with checked arithmetic;
there is no awk/find/du dependency or accounting redirection. Permission/I/O
errors and descriptor exhaustion fail closed. Very large individual artifact
trees may exceed the process's descriptor limit; they are preserved. Run from
another checkout when pruning a target containing the running xtask executable:
its mapping correctly makes that target busy.

When remote-accept sees less than 40 GiB free, it logs an idle-only pruning
attempt before refusing. The client invokes a prebuilt native xtask helper over
SSH, targeting `gate-worktree/target` with the default two-day threshold, then
checks free space again. The helper runs the same Rust pass and claims the
checkout guard before the zero-wait exclusive host lease. Install it on each
remote gate host from the desired reviewed source in your own checkout:

```sh
just lease carrick cargo build --locked -p carrick-xtask
mkdir -p /Volumes/carrick/dev/build-tools
install -m 755 target/debug/carrick-xtask /Volumes/carrick/dev/build-tools/carrick-xtask
```

Install/update while the helper is idle. `CARRICK_TARGET_PRUNER` in the host's
`env.sh` can select another prebuilt native helper. The remote request requires
the `target-prune --protocol fd-v1` interface; absent or older helpers fail
closed, with no shell removal fallback. Low-disk recovery needs no Cargo run,
build or gate checkout mutation. A busy lock, unavailable root lsof or helper,
or insufficient reclaimed space preserves the 40 GiB refusal. The helper
honors the existing `CARRICK_HOST_LEASE_PATH` environment plumbing.
