# `carrick build`: image building by running a real builder as a guest

**Status:** design approved; not yet executed. A gated extension to the
ecosystem work (the carrick-serve spec
[2026-06-05-carrick-serve-engine-api-design.md](2026-06-05-carrick-serve-engine-api-design.md)
deferred build). **Pivoted 2026-06-06** after a live spike: instead of a
carrick-native Rust builder, `carrick build` **runs the real
[kaniko](https://github.com/GoogleContainerTools/kaniko) builder as a carrick
guest**, and carrick's job is to be a complete-enough Linux kernel for it. (The
earlier native-builder draft — layer committer, store-write serializers,
single-stage — is superseded; see [§5](#5-why-this-beats-a-native-builder).)

**Date:** 2026-06-06.

**Scope:** make carrick produce OCI images by running kaniko as a guest, plus a
thin `carrick build` CLI wrapper, loading kaniko's output into carrick's store,
and a legacy `POST /build` in `carrick serve`. The substantive work is **closing
the carrick coverage gaps kaniko exercises**, starting with the one the spike
found. **Not** in scope: a carrick-native builder; privileged builders
(`buildkitd`/`buildah`/`dockerd`) that need `mount`/`pivot_root`/overlayfs; the
BuildKit gRPC frontend (see [Non-goals](#non-goals)).

---

## 1. Goal

Make `carrick build -t app .` build a Dockerfile into a real, portable OCI image
— by **running kaniko as a guest**, not by reimplementing a builder. carrick
already runs unmodified Linux binaries; kaniko is a Linux binary that builds
images **without** privileged container setup (no `mount`/`pivot_root`/overlayfs
— it execs each `RUN` in-process over its own root filesystem and snapshots
changes in userspace). So the build engine is kaniko; carrick supplies the
syscalls. carrick's deliverable is (a) close the gaps kaniko hits, (b) a thin
`carrick build` wrapper, (c) load kaniko's output into the store so `carrick run
<tag>` works, (d) `POST /build` so `docker build -H …` reaches it.

## 2. The spike (why this is the chosen design — validated, not hypothetical)

A live spike on 2026-06-06 ran the kaniko executor under carrick:

- **Boots & runs.** `carrick run gcr.io/kaniko-project/executor:latest version` →
  `Kaniko version : v1.24.0`, exit 0. The (large, Go) builder binary runs.
- **Pulls over the network from inside the guest.** Building `FROM alpine:3.20`,
  kaniko retrieved the alpine manifest from `index.docker.io` over TLS from within
  the guest — Go's registry/TLS client works under carrick.
- **The build is correct (Docker oracle).** The *identical* kaniko invocation
  under real Docker (`docker run … kaniko … --no-push --tar-path out.tar`)
  succeeded end-to-end: unpacked alpine, ran both `RUN` steps (printed the proof
  string, ran `apk add`), snapshotted the FS, applied `ENV`/`CMD`, and produced a
  4.65 MB OCI image tar. So the invocation and kaniko itself are sound.
- **One carrick blocker, root-caused.** Under carrick, kaniko fails at
  `unlinkat /etc/services: read-only file system` during "Unpacking rootfs," before
  the first `RUN`. Cause (confirmed): `/etc/services` is a **carrick synthetic VFS
  injection** (`vfs/etc_services.rs` — injected so glibc/Go port lookups work under
  the `--fs host` scratch), mounted read-only in `VfsMounts`; kaniko's `unlinkat`
  to replace it with alpine's routes to the synthetic mount's mutator → `EROFS`,
  instead of falling through to the writable overlay (`HostFsBackend::mark_deleted`,
  which deletes *real* rootfs files fine). A guest cannot override an injected
  `/etc/*` file. This is a **narrow, general carrick correctness gap** (§7), not a
  dead end.

**Conclusion:** kaniko-as-guest gets ~95% of the way on the first attempt, blocked
by a single fixable VFS bug. The approach is viable; the work is gap-closing.

## 3. Architecture

```
carrick build -t app -f Dockerfile <context>
  → resolve the kaniko executor image (pinned; pulled/cached in the store)
  → carrick run --fs host  (writable overlay; max_traps unbounded)
        -v <context>:/workspace
        gcr.io/kaniko-project/executor:<pin>
        --context dir:///workspace --dockerfile /workspace/<Dockerfile>
        [--build-arg…] [--cache…] [--destination app | --no-push --tar-path …]
     ⇒ KANIKO does everything: parse (incl. multi-stage), pull bases, exec each
       RUN as a (nested) carrick guest, snapshot the FS in userspace, assemble
       layers + config + manifest, and either PUSH to a registry or write a tar.
  → if --no-push: carrick LOADS the output tar into its own store (so
       `carrick run app` / `carrick serve` can use it).
```

**carrick's role is the kernel + a thin wrapper.** It does not parse Dockerfiles,
diff layers, or write image metadata — kaniko does, exactly as it does under
Docker. carrick: runs the guest (`--fs host`, uncapped traps), maps CLI flags to
kaniko flags, bind-mounts the context, and on `--no-push` ingests kaniko's tar via
the store's load path. RUN steps run as real carrick guests — the same emulation
`carrick run` already provides.

**Two output modes:**
- **`--push` / `--destination <ref>`** — kaniko pushes the built image directly to
  a registry (it has its own registry client + auth; the spike proved guest-side
  registry TLS works). carrick does nothing extra.
- **`--no-push` (default for local builds)** — kaniko writes a `--tar-path` image
  tarball; carrick **loads** it into the store (the `load` produce-verb, §6) and
  applies the `-t` tag, so `carrick run app` works immediately.

## 4. The gap-closing program (the real work)

The spike shows the design is gated by carrick coverage, not by missing builder
code. So the bulk of this goal is a **conformance-driven loop**, the same shape as
the existing LTP/language-runtime conformance work:

1. Run kaniko under carrick on a build from the corpus.
2. It fails on a syscall/VFS gap (the spike's was synthetic-`/etc` `EROFS`).
3. Root-cause with `carrick trace`/the event ring; fix the gap in the runtime;
   add an owning probe/test (per the project's conformance discipline).
4. Re-run; advance to the next gap. Repeat until the corpus builds.

The **first gap is known and designed in §7**. Subsequent gaps are discovered by
running, not guessed — kaniko's heaviest surfaces are: full-filesystem snapshot
each step (mass `stat`/`readdir`/xattr), exec of freshly-written base binaries,
tar+gzip, and registry push (TLS). The spike already exercised most of these
successfully up to the `/etc/services` unlink. The corpus + matrix (§9) make
"which builds work" measurable, exactly like `support-matrix.md`.

## 5. Why this beats a native builder

The pivot **resolves**, by delegation to kaniko, every hard problem the native
draft wrestled with:

| Native-builder problem | Status under kaniko-as-guest |
|---|---|
| Net-new layer-committer (invert `rootfs.rs`; whiteouts; determinism) | **Gone** — kaniko produces layers + does its own userspace snapshot/diff. |
| Net-new store-write serializers (`config.json`/manifest/`PullSummary`; `resolve()` is lossy) | **Gone for the produce path** — kaniko writes a standard image (tar/registry); carrick only needs the existing-style **load** to ingest a tar. |
| Single-stage only | **Multi-stage comes free** — kaniko supports it natively. |
| Portability (carry mode/uid/gid/xattrs so other runtimes extract right) | **Free** — kaniko emits standard OCI; the Docker-oracle tar is a normal image. Portability is kaniko's (battle-tested) concern. |
| Build cache (hand-rolled, deterministic-digest correctness) | **Free** — kaniko has a mature `--cache` (registry/dir-backed layer cache). |
| Matching exact Docker build semantics (`.dockerignore`, ARG order, shell/exec forms, base-config inheritance) | **Free** — it's the real builder. |

What remains is carrick coverage (which benefits *every* guest, not just build) +
a thin wrapper. This is strictly less reimplementation and strictly higher
compatibility — and it is the purest expression of carrick's thesis.

## 6. `carrick build` CLI + produce verbs

- **`carrick build [-t name[:tag]] [-f Dockerfile] [--build-arg K=V]…
  [--no-cache] [--cache-repo R] [--push|--no-push] [--platform …] <context>`** —
  the wrapper. Validates the context, resolves the pinned kaniko image, runs the
  §3 guest invocation, maps flags to kaniko flags, and on `--no-push` loads the
  output tar + tags it. Errors are kaniko's, surfaced verbatim; a non-zero kaniko
  exit (or a carrick `trap_limit_hit`) fails the build.
- **`carrick load -i <tar>`** — ingest a docker-archive/OCI-layout tar (kaniko's
  output, or any `docker save` tar) into the store. **This is the one produce-side
  serializer carrick must build** — and it is the *read/ingest* direction (write
  blobs + `manifest.json`/`config.json`/`carrick-image.json` from the tar), which
  the store's pull path already largely models. Used by `carrick build --no-push`.
- **`carrick push <image> [<ref>]`** — still useful for pushing *stored*
  (pulled or loaded) images carrick didn't build; wire `oci-client` push +
  existing `Basic` auth. (A kaniko `--push` build pushes directly and needs none of
  this.) Optional for this goal; include if cheap.
- **`carrick save` / `history` / `tag`** — `tag` exists; `save`/`history` are nice
  to have but **not required** (kaniko + `load` cover the build→run→push loop).
  Deferred unless trivial.

So the produce-side serializer burden collapses from "config/manifest/PullSummary
writers + a layer committer" (native draft) to **just `load`** (ingest), because
kaniko authors the image.

## 7. The first gap: guest override of synthetic `/etc/*` injections

The spike's blocker, designed as the first fix (general-purpose, not build-only):

carrick injects synthetic read-only `/etc/services` (and `/etc/resolv.conf`, and
seeds `/etc/hosts`/`passwd`/`group`/`nsswitch`) so name/port lookups work under the
`--fs host` scratch (`vfs/etc_services.rs`, `vfs/mod.rs`, `fs_setup.rs`). Today a
guest cannot `unlinkat`/overwrite an injected node — the synthetic VFS mount's
mutator returns `EROFS` (`vfs/bind.rs`). **Fix: copy-up / override semantics** — a
guest `unlink` or write of an injected `/etc/*` path **detaches the injection** and
falls through to the writable overlay, so the guest's version wins (and a
subsequent read sees the guest's file, not the injection). This matches Linux
(these are just files a container may replace) and fixes a real, common gap beyond
build: **many real workloads rewrite `/etc/resolv.conf`**, and today they'd hit the
same `EROFS`. Owning probe: a guest that `unlink`s `/etc/services` then writes its
own and reads it back; differential vs Docker.

(Subsequent gaps are handled by the §4 loop, not pre-designed.)

## 8. `POST /build` in `carrick serve`

Legacy (non-BuildKit) builder protocol: gzipped context tar as the body
(`?dockerfile=`/`?t=` (repeatable)/`?buildargs=` URL-encoded JSON/`?nocache=`/
`?pull=`). The handler unpacks the context and **shells out to `carrick build`**
(which runs kaniko) — the established server-as-translator pattern (no guest fork
in the server's tokio runtime). It streams kaniko's progress as protocol NDJSON
(`{"stream":…}`, `{"aux":{"ID":…}}`, `{"errorDetail":{"message":…}}`).

**Streaming is net-new in serve** (today's handlers return a single buffered
`Full<Bytes>`, `router.rs:56-97`): `/build` needs a streaming response body
(`StreamBody`/`BoxBody` + a channel pumping the child's stdout, `Transfer-Encoding:
chunked`; hyper 1.9 + http-body-util 0.1 support it) and its own query parser (the
existing `query_param` can't do repeated `?t=` or URL-encoded JSON). Enables
`DOCKER_BUILDKIT=0 docker -H unix://…/carrick.sock build` and compose `build:`.

## 9. Experimental posture

Build is **experimental** because it depends on carrick's still-maturing syscall
coverage — surfaced and closed by the §4 loop, not an accepted ceiling. RUN steps
(and kaniko itself) run with `max_traps` effectively unbounded (no syscall-count
cap; a wall-clock timeout MAY bound a hung build; `trap_limit_hit` → build
failure). Success is a **growing Dockerfile corpus** published as a matrix vs
`docker build` (kaniko-under-Docker as oracle), starting from the spike's
`FROM alpine + RUN + ENV/CMD` case.

## 10. Milestones

### M0 — First green build (fix the spike blocker)
Implement §7 (guest override/copy-up of synthetic `/etc/*`); re-run the spike's
Dockerfile under carrick.
**Exit:** `carrick run --fs host … kaniko … --no-push --tar-path out.tar` on the
spike Dockerfile produces a tar; its contents match the Docker-oracle build
(same files, the `/proof.txt`); an owning probe covers the `/etc/*`-override
behavior. (If a *next* gap appears before the tar is produced, M0 expands to fix
it — M0 is "kaniko builds one trivial image under carrick.")

### M1 — `carrick build` wrapper + load-into-store
The `carrick build` CLI (flag→kaniko mapping, pinned kaniko image, `--fs host`,
uncapped traps); `carrick load` ingesting the kaniko output tar + tagging.
**Exit:** `carrick build -t t1 .` (no docker) builds the spike Dockerfile and
`carrick run t1` executes it (`cat /proof.txt` → the proof string); a failing
`RUN` fails the build with kaniko's captured output.

### M2 — Corpus + cache (gap-closing)
Drive a Dockerfile corpus (multi-stage; `COPY`; `RUN` coreutils; `RUN apt-get`/
`apk add`; `ENV`/`WORKDIR`/`USER`) through `carrick build`, closing each carrick
gap the §4 loop surfaces with an owning probe; enable kaniko's `--cache`.
**Exit:** the corpus builds under carrick (or each non-builder is a filed,
tracked carrick coverage gap), published as a matrix vs `docker build`; a re-build
hits kaniko's cache.

### M3 — `POST /build` (streaming)
Streaming response body + query parser in serve; `POST /build` shelling to
`carrick build`.
**Exit:** `DOCKER_BUILDKIT=0 docker -H unix://…/carrick.sock build -t app .`
builds a simple image end-to-end with streamed output.

## 11. Acceptance rules

1. Every carrick gap a build hits is closed with an **owning probe/test** and a
   `docker`-oracle comparison (the project's conformance discipline) — not patched
   ad hoc.
2. No `RUN`/kaniko step is killed by a syscall/trap cap; failures are real
   non-zero exits, `trap_limit_hit`, or filed coverage bugs.
3. Built images are validated runnable (`carrick run` the result) and, where a
   `docker build`/kaniko-under-Docker oracle exists, compared.
4. `carrick build` runs the **real** kaniko (a pinned version) — no forked/
   reimplemented builder; carrick's code is the wrapper + the coverage fixes + `load`.
5. `POST /build` reuses `carrick build` via subprocess (no guest fork in the
   server's tokio runtime) and adds the streaming body as a new serve capability.

## 12. Non-goals

- **A carrick-native Rust builder** — superseded by kaniko-as-guest. (If kaniko
  ever proves unviable on some axis, the native design is the documented fallback,
  but it is not the plan.)
- **Privileged builders** (`buildkitd`, `buildah`, `dockerd`) as guests — they
  need `mount`/`pivot_root`/overlayfs/full mount-namespaces (all **Deferred** in
  carrick; explicitly scoped out by the namespaces design). kaniko is chosen
  *precisely because* it is mount-free. Running the privileged stack is a separate,
  much larger coverage north-star.
- **BuildKit gRPC frontend / buildx** — modern `docker build` defaults to
  BuildKit; v1 targets the legacy `POST /build` (`DOCKER_BUILDKIT=0`).
- **Bundling a forked kaniko** — carrick runs upstream kaniko unmodified at a
  pinned version.

## 13. Risks & open questions

- **The next gap after `/etc/*` is unknown until we fix and re-run.** kaniko
  snapshots the *full* filesystem each step (mass `stat`/`readdir`/`lstat`/xattr),
  execs base binaries it just wrote, and does heavy tar/gzip — any could surface a
  carrick gap. The §4 loop is built for exactly this; M0/M2 are scoped as
  "close gaps until it builds," and the spike already cleared the path up to the
  one known blocker. Honest framing: M2 is **open-ended** (bounded by the corpus),
  so the corpus is kept small and representative.
- **kaniko full-FS snapshot is slow** (it walks `/` per step). Acceptable for
  experimental v1; kaniko's `--snapshot-mode=redo`/`time` and `--cache` mitigate.
- **kaniko version pinning + distribution.** Pin a known-good tag; document how
  `carrick build` resolves it (pull on first use into the store). A kaniko upgrade
  could surface new gaps — pin and bump deliberately.
- **`--push` auth from the guest.** kaniko reads Docker credential config; how
  carrick surfaces host registry creds into the guest (env/`-v` the docker config)
  needs a small design in M1. The spike used anonymous pull only.
- **`load` fidelity.** Ingesting kaniko's tar must round-trip into a `carrick
  run`-able store image; M0/M1 validate against the Docker-oracle tar. This is the
  one serializer carrick still owns (ingest direction).
- **Determinism/portability** are kaniko's, not carrick's — a strict improvement
  over the native draft.

## Appendix — spike evidence + anchors (2026-06-06)

- Spike: `carrick run gcr.io/kaniko-project/executor:latest version` → `v1.24.0`,
  exit 0. `carrick run --fs host -v /tmp/ctx:/workspace … executor --context
  dir:///workspace --no-push --tar-path …` → `unlinkat /etc/services: read-only
  file system` at "Unpacking rootfs." Identical `docker run … executor …` →
  success, 4.65 MB `out.tar`.
- Synthetic `/etc/services` injection: `crates/carrick-runtime/src/vfs/etc_services.rs`
  (`ETC_SERVICES_PATH`), routed via `vfs/mod.rs` `VfsMounts`; read-only mutator
  `EROFS`: `vfs/bind.rs:23,347…`. Real-rootfs delete works:
  `HostFsBackend::mark_deleted` (`fs_backend.rs:2321`), test
  `host_unlink_hides_rootfs_path` (`fs_backend.rs:3609`). `unlinkat` dispatch:
  `dispatch/fs.rs:6670`. Other `/etc` seeds: `fs_setup.rs:151-203`.
- Mount/pivot_root/chroot/setns **Deferred** (why privileged builders are out):
  `crates/carrick-hvf/src/syscall.rs:209,210,220,436,503-506`; namespaces design
  scopes mount out: `docs/namespaces-design.md:71`.
- serve buffers (streaming is net-new) + `query_param` limits:
  `crates/carrick-cli/src/serve/router.rs:32-37,56-97`; subprocess pattern:
  `serve/spawn.rs`.
