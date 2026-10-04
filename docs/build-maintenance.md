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
