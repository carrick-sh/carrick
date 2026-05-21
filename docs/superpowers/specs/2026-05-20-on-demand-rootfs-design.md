# On-Demand Rootfs (`--fs host`) — Design

**Date:** 2026-05-20
**Status:** Proposed (awaiting review)
**Branch:** `feat/reduce-rss`

## Problem

Running a Debian guest costs **~573–615 MB RSS** for even `/bin/true`, and `carrick run` has a ~0.37s fixed startup. Empirically attributed (see [[process-overhead]] memory + `examples/hvf_vm_lifecycle_bench.rs`, `fork_cost_bench.rs`, `rss_probe.rs`, `vmmap`):

- Guest/HVF memory is already lazy (16 KB resident of the 64 MB+ windows). NOT the problem.
- The RSS is **host heap holding the decompressed OCI rootfs**: the in-memory `RootFs` keeps every file's bytes as `Vec<u8>` (`src/rootfs.rs`), built from `Tar(Vec<u8>)`/`TarGz(Vec<u8>)` layer blobs. ~244 MB live + transient decompression buffers (peak ~600 MB). Scales with image size (Alpine = 64 MB).
- Under `--fs host` this is **pure duplication**: `HostFsBackend::seed_from_rootfs` already extracts the entire rootfs to the cap-std scratch Dir on disk, and `HostFsBackend` already serves `lookup`/`metadata`/`read`/`readdir` authoritatively from that Dir. Its own comments anticipate the in-memory `RootFs` being dropped (`src/fs_backend.rs:666`, `:720`).

## Goal

Under `--fs host`, eliminate the in-memory rootfs entirely — both the steady-state ~244 MB and the ~600 MB load-time peak — by **streaming OCI layers directly to the scratch Dir** and running with the Dir as the sole rootfs source. Target: Debian `/bin/true` RSS from ~600 MB to tens of MB. `--fs memory` is unchanged.

## Non-goals

- Changing `--fs memory` (keeps the in-memory `RootFs`).
- Improving metadata fidelity beyond what `--fs host` already provides (uid/gid → synthesized; mtime/special files already dropped). This change keeps the *same* fidelity envelope, it does not regress or improve it.
- The ~10.8 ms/fork+exec cost (separate; expected to improve as a side effect of less held memory, but not a goal here — measure, don't promise).

## Approach (chosen)

**Streaming layer extraction → cap-std scratch Dir; no in-memory `RootFs` retained under `--fs host`.**

### Components

1. **Streaming extractor** — new function, `oci`/`rootfs` boundary, e.g. `extract_layers_to_dir(layers, &cap_std::fs::Dir) -> Result<()>`.
   - For each layer **in order**: wrap the blob in a streaming `flate2` decoder (gzip) → `tar::Archive`; iterate entries, writing each **directly** into the Dir via cap-std (`create_dir_all`, `write`, `symlink`, `set_permissions` from the tar mode).
   - Apply OCI overlay semantics across layers: later layers override earlier (overwrite); **whiteouts** (`.wh.<name>`) delete the target in the Dir; **opaque dirs** (`.wh..wh..opq`) clear the directory's prior contents. (Replicates the logic currently in `RootFs::from_layers`, but as disk ops — verify against that implementation during planning.)
   - Memory ceiling: one tar entry + one gzip window at a time. Never the whole tree.
   - **Fidelity (unchanged from today's `extract_to_disk`):** preserve mode bits (`set_permissions`) and symlinks; uid/gid not preserved (unprivileged macOS → owner 501; backend synthesizes Linux uid=0); mtime/xattrs not preserved; **special files** (device/fifo/char/block) — skip and fire a `partial-syscall`/compat probe (current model already drops them; `/dev` is synthetic via `vfs/dev`). **Hardlinks** — materialize as a copy (or real hardlink via cap-std if same Dir); pick copy for simplicity unless tests show a consumer needs shared inodes.

2. **Host-backed dispatcher construction** — under `--fs host`, build the dispatcher with the `HostFsBackend` Dir as the authoritative rootfs and **no in-memory `RootFs` base**. The backend already implements disk-authoritative `lookup`/`metadata`/`read`/`readdir`. Requires the dispatcher/VFS rootfs read path to support "no in-memory base" (today `with_rootfs` takes a `RootFs`; add a host construction path that doesn't retain one). Drop layer blobs after extraction.

3. **`--fs memory` unchanged** — still `RootFs::from_layers` in RAM; the in-memory tree remains the source of truth there.

### Data flow (`--fs host`)

```
pull/load layer blobs (Vec<u8> or file handles)
  → extract_layers_to_dir(layers, scratch_dir)   [streaming; overlay+whiteout]
  → drop layer blobs
  → dispatcher{ rootfs: HostFsBackend(scratch_dir), no in-mem base }
  → guest fs syscalls resolve against the Dir (lookup/read/metadata/readdir)
```

### Error handling

- Extraction errors (bad tar, gzip CRC, write failure) abort the run with a clear `RootFsError`/`OciBootstrapError` naming the layer + entry.
- Path-escape safety: cap-std refuses writes outside the Dir; tar entries with `..`/absolute paths are normalized/rejected (cap-std enforces, plus existing `normalize`).
- Whiteout of a non-existent path is a no-op (later layers may whiteout something already gone).

### Affected files

- `src/oci.rs` and/or `src/rootfs.rs` — add the streaming extractor; the tar/whiteout parsing currently inside `RootFs::from_layers` is the reference (consider extracting shared whiteout/path-normalize helpers so memory + host paths don't drift).
- `src/fs_backend.rs` — `HostFsBackend` gains a "seed by streaming extraction" constructor (replaces `seed_from_rootfs(&RootFs)` for the host path; keep the old one if `--fs memory` tests use it, or migrate).
- `src/dispatch/mod.rs` (+ `src/vfs`) — a dispatcher construction path for `--fs host` that uses the backend Dir as authoritative with no retained `RootFs`.
- `src/main.rs` — `run`/`run-elf` host path wires the streaming extractor + the no-base dispatcher.

### Testing

- **Unit (streaming extractor, against a `tempfile`/cap-std Dir):** single layer (files/dirs/symlinks + mode bits preserved); multi-layer override (later wins); whiteout deletes; opaque dir clears; special file skipped (+ probe); hardlink materialized; path-escape rejected.
- **Integration:** existing Docker conformance suite stays green; `apt-get install -y hello` end-to-end still prints `Hello, world!` (the v1.0 gate); `/bin/true` + `ls`/`cat` on debian behave identically.
- **Perf assertion (manual, recorded):** Debian `/bin/true` RSS before/after (`/usr/bin/time -l` peak + `vmmap` steady-state). Expect ~600 MB → tens of MB, peak too. Note any fork+exec latency change.

### Risks

1. **Whiteout/opaque parity** with the in-memory path — if `from_layers` handles an edge case (opaque dirs, nested whiteouts) the streaming path misses, a file wrongly appears/disappears. Mitigation: share the whiteout-decision helper; test each case.
2. **Metadata reconstruction** — `backend.metadata()` must yield Linux-plausible mode/uid for every entry now that there's no in-memory fallback. Mitigation: it's already the `--fs host` source of truth; conformance + a metadata-focused test covers it.
3. **Performance of per-entry disk writes** — many small files (Debian rootfs ~thousands) → syscall-heavy extraction. Mitigation: this already happens in `extract_to_disk`; streaming shouldn't be slower and removes the in-memory build. Measure.
4. **`--fs memory` divergence** — two rootfs code paths (in-memory vs disk) risk drift. Mitigation: shared tar-parse/whiteout helpers; both exercised by conformance.

## Open question for review

- Should `seed_from_rootfs(&RootFs)` be **removed** (host always streams) or **kept** for `--fs memory`→disk scenarios/tests? Leaning: keep `RootFs::from_layers` for `--fs memory`, add the streaming path for `--fs host`, share helpers; remove `seed_from_rootfs` only if no caller remains.
