# `carrick exec` + its foundation — design

**Status:** approved design, not yet implemented.
**Goal:** implement `docker exec`-equivalent for carrick — run a command in a
running container, sharing **both** its writable filesystem and its PID
namespace — plus the persisted/shareable container state that makes it possible.
**Roadmap:** P3 of `docs/docker-compat-audit.md` (the connective lifecycle verb
that makes `run -d` usable); also lays the groundwork P5 (`create`/`start`/
`restart`) needs.

---

## 1. Scope & invariant

`exec` only ever targets a **detached (`run -d`) container** — foreground runs
are attached and exit, so there is nothing to exec into. This bounds the work:

- **Only detached runs** get the persisted, shareable state (run config,
  file-backed region, on-disk overlay). Foreground runs keep their ephemeral
  `TempDir` overlay and `MAP_ANON` region unchanged.
- **`exec` requires `--fs host`.** A `--fs memory` overlay lives in the running
  container's process and cannot be shared with a separate process; `exec` on
  such a container is a clear error, not a silent fresh filesystem.

`exec` is implemented as a **new guest in its own HVF VM** (carrick is one host
process per guest process) that *joins* the target container's filesystem and
PID namespace. It does not inject into the running guest's address space.

---

## 2. Pieces (each independently landable)

### A. Persist run config in the registry

`ContainerState` (`crates/carrick-runtime/src/container.rs`) gains a `RunConfig`
holding what `exec` (and later `start`) needs to reconstruct a compatible
`RunSpec`:

- image reference, platform, fs backend kind,
- env, workdir, uid/gid, pid mode,
- **scratch path** (the on-disk overlay, see C),
- **region path** (the file-backed pid region, see B).

Written at `run -d` time. The field is additive and `#[serde(default)]` so
existing registry entries still deserialize. Independently valuable: it enriches
`inspect` and is the prerequisite for `start`/`restart`.

### B. File-backed PID region (the pid-ns join)

Today the supervisor's shared region is `mmap(MAP_SHARED | MAP_ANON)`
(`namespace/pid.rs:178`) — coherent across `fork`, but an unrelated process
cannot attach to it (no name/fd). To let `exec` join the namespace:

- **Region sharing = file-mmap** (chosen over POSIX shm): a detached container's
  `alloc_region` mmaps a file at `<registry>/<id>/region` (`MAP_SHARED` over an
  fd) instead of `MAP_ANON`. The supervisor + guest-init still inherit it across
  `fork` exactly as today; the only change is that an outside process can now
  `mmap` the same file. The region struct is already POD and shared-across-fork,
  so it is layout-stable for file backing.
- New `attach_region(path)` maps the existing file for the `exec` side.
- The file lives under the container dir, so `rm`'s existing `remove_dir_all`
  cleans it up for free.

**How `exec` joins without the registration pipe:** `exec` writes its own member
slot into the region. The supervisor's existing **1 s periodic rescan**
(`arm_member_watches` on the kqueue timeout) arms the `EVFILT_PROC` watch on the
new member within ~1 s — no inherited pipe fd needed. `exec`'s own CLI process
owns its guest's lifecycle and reaping (the guest is `exec`'s child); region
membership gives the guest a ns-pid and visibility of the container's pids.
Supervisor watching the exec member is a bonus for orphan-reaping `exec`'s
grandchildren.

### C. Stable shared overlay (`--fs host`)

`HostFsBackend::new()` currently owns a `tempfile::TempDir` that auto-deletes.
For detached `--fs host` runs:

- create the scratch at `<registry>/<id>/scratch` (persisted, **not** a
  `TempDir`),
- add `HostFsBackend::attach(path)` — open an existing scratch root **without**
  owning or deleting it (used by `exec`),
- cleanup rides on `rm`'s `remove_dir_all` of the container dir.

Foreground/`run-elf` paths keep `HostFsBackend::new()` (ephemeral) unchanged.

### D. `exec`

```
carrick exec [-i] [-t] [-u user] [-w dir] [-e KEY=VAL] <container> <cmd>…
```

(`-d` detached exec is a fast-follow — see §7 — so v1 runs `exec` attached.)

1. Resolve `<container>` → load `RunConfig`. Error if not running, or if
   `fs_backend != host`.
2. Build a `RunSpec`: the image's rootfs layers (re-resolved from the image
   store via the persisted ref) + `HostFsBackend::attach(<id>/scratch)` + the
   **exec command** (not the container's command) + env/workdir/uid merged
   (CLI flags override the container's `RunConfig`).
3. Set `CARRICK_JOIN_REGION=<registry>/<id>/region` so the runtime **attaches**
   to the existing region as a new member instead of allocating one and forking
   a supervisor (the container already has a supervisor).
4. Run the guest in its own HVF VM, reusing the run path's pty (`-t`) / raw
   streaming and exit-code propagation.

The existing odd `Commands::Exec { context, command }` arg shape is replaced by
this docker-shaped one.

---

## 3. Error handling

- `--fs memory` container → `exec requires a container started with --fs host`.
- Unknown / not-running container → docker-style `no such container: X` /
  `container X is not running` (reuse `container::resolve` + the `init_alive`
  check from the lifecycle subcommands).
- Region attach failure → hard error (never silently run outside the namespace,
  which would mislead).
- A post-fork failure in the exec guest follows the same `_exit`-on-error
  discipline as the run path (the forked-init fix already landed).

---

## 4. Testing

- **Unit:** `RunConfig` serde round-trip (incl. default-on-missing); the
  file-backed region — two processes (a forked child) `mmap` the same region
  file, one writes a member slot, the other reads it (mirrors the existing
  `MAP_SHARED|MAP_ANON` region unit tests, but file-backed);
  `HostFsBackend::attach` — write a file through one handle, read it through a
  second handle on the same path.
- **End-to-end (signed binary):** `run -d --fs host` a container that writes a
  sentinel file and sleeps; `exec` a shell and confirm (a) it reads the
  sentinel the container wrote (shared overlay), (b) `ps`/`/proc` shows the
  container's init as pid 1 (shared pid-ns), (c) exit-code passthrough
  (`exec … sh -c 'exit 7'` → 7). Self-skips without HVF, like the other
  HVF-gated tests.

---

## 5. Approach choices (decided)

- **Region sharing = file-mmap** under the container dir (vs POSIX shm):
  co-located with the container's other state, free cleanup via `remove_dir_all`,
  simplest layout-stable option.
- **Scratch under the container registry dir** (vs a separate scratch root): one
  `remove_dir_all` cleans the overlay, region, logs, and state together.

---

## 6. Phasing

Land each piece behind its tests, lowest-risk first:

1. **A — persist run config.** Additive serde; enriches `inspect`; no behavior
   change. Low risk.
2. **C — stable overlay + `attach`.** Detached `--fs host` writes its scratch
   under the container dir; `attach` reads it. Low risk (foreground unchanged).
3. **B — file-backed region + `attach_region`.** The riskier rework; gated by
   the two-process region test and re-running the pid-ns conformance probes.
4. **D — `exec`.** Ties A+C+B together; the new command + end-to-end test.

A and C are independently useful even before D. Each phase is its own commit(s).

---

## 7. Out of scope (follow-ups)

- `exec -d` detached exec lifecycle tracking in the registry (v1 may run it
  attached only; `-d` can be a fast-follow).
- `--fs memory` exec (architecturally unshareable; permanent constraint).
- Supplementary-group / user-name resolution for `exec -u` (shares the `--user`
  follow-ups already tracked).
- `start`/`restart` (P5) — unblocked by piece A but separate work.
