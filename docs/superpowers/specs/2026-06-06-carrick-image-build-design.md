# `carrick build`: image building (the OCI produce side)

**Status:** design approved; not yet executed. A gated extension to the
ecosystem work — the carrick-serve spec
([2026-06-05-carrick-serve-engine-api-design.md](2026-06-05-carrick-serve-engine-api-design.md))
deferred image *build* as "its own gated goal." This is that goal. **Revised
2026-06-06** after an adversarial code-grounded review (the original draft
misread the `--fs host` scratch as an upper overlay; §5/§8 below are rewritten
around a host-side diff instead).

**Date:** 2026-06-06.

**Scope:** make carrick an OCI image **producer**. A `carrick build` CLI for
**single-stage** Dockerfiles, the produce-side verbs (`push`/`save`/`load`/
`history`/`tag`), and a legacy `POST /build` endpoint in `carrick serve`. **Not**
in scope: BuildKit/buildx, multi-stage, `ADD`-from-URL, `RUN --mount`
cache/secret/ssh, cross-arch build (see [Non-goals](#non-goals)).

---

## 1. Goal

Close the produce side of the container supply chain. Today carrick pulls and
runs any OCI image but cannot make one — `build`/`push`/`save`/`load` are absent,
so the inner loop "edit Dockerfile → build → run" is impossible. This goal ships
a build engine: a Dockerfile drives a sequence of OCI layers, each produced by
writing build-context files (`COPY`) or running a command in a carrick guest
(`RUN`) and capturing the change, assembled into an image in carrick's
already-OCI-shaped store and runnable immediately.

## 2. Why this shape

Build was deferred (vs near-free `save`/`push`) because it needs a **net-new
layer-diff/commit subsystem** AND it must **write** images into a store that today
only ever *pulls* them. v1 is single-stage so the novel core (RUN-in-guest +
host-side diff + the store write path) is proven before multi-stage/ADD. It
couples to carrick-serve: `POST /build` is a milestone of *this* spec.

## 3. What exists today (grounded against the code)

- **No produce verbs** anywhere. **No production tar-layer writer** (the only
  `tar::Builder` is test-only, `rootfs.rs:874`).
- **The store is OCI-shaped but write-once-via-pull.**
  ([`carrick-image/src/lib.rs`](../../../crates/carrick-image/src/lib.rs)):
  `blobs/sha256/<hex>`, `manifest.json`, `config.json`, and a per-image
  **`carrick-image.json`** (a `PullSummary`: ordered layer digests/sizes/paths +
  image ref) which is the **key that `resolve`/`tag`/`list` read** (`lib.rs:577`,
  `:810`, `:657`). `pull_image` is the **sole writer**, and it writes `config.json`
  from **raw registry bytes**. There is **no `ImageConfig`→`config.json`
  serializer, no manifest builder, no `PullSummary` writer** — building an image
  needs all three (see §9).
- **`resolve()` is lossy.** `OciImageConfigInner` parses only the runtime `Config`
  block (user/env/entrypoint/cmd/workdir/labels/exposed_ports/stop_signal,
  `lib.rs:527-537`); it **drops `rootfs.diff_ids`, `history`, `architecture`,
  `os`, `created`** — all of which a built image must author itself.
- **`rootfs.rs` is the read/apply side.** It *applies* `.wh.<name>` /
  `.wh..wh..opq` whiteouts when stacking layers *down* (`apply_layer` (private)
  `:546`, constants `:95-96`). The committer reuses the constants (module-private
  → committer lives in `rootfs.rs` or gets a `pub(crate)` re-export) and the
  public extract/compose API (`RootFs::from_layer_paths`, `:379`;
  `extract_layer_paths_to_dir`, `:213`).
- **`--fs host` is a MERGED rootfs, not an upper overlay** (the original draft's
  fatal misread). `HostFsBackend::extract_layers` streams *every* layer into one
  cap-std dir — "after this call, the backend **is** the rootfs"
  (`fs_backend.rs:984-998`). `mark_deleted` does a real `remove_file`/`remove_dir`
  and **records nothing**; `deleted_child_names` returns empty ("disk-authoritative:
  deletions are real unlinks, no tombstones", `fs_backend.rs:2321-2330,2383-2388`).
  The `OverlayEntry::Deleted` tombstone exists **only in `MemoryBackend`**, whose
  `open_raw_fd → None` (`:728-733`) means it **cannot host a fork/exec'd guest**.
  ⇒ A built layer **cannot** be recovered by "walking the upper scratch"; it must
  be computed by **diffing** the post-step tree against the known pre-step tree
  (§5).
- **Guest-visible file metadata lives in xattrs.** carrick forces owner-rw on disk
  and can't `chown` as non-root macOS, so the real guest mode/uid/gid are in
  `user.carrick.mode|uid|gid` xattrs, read via `HostFsBackend::real_stat` /
  `fd_carrick_meta` (`fs_backend.rs:1542-1570,1664,3062`). The committer reads
  metadata through that xattr-aware path and **strips all `user.carrick.*`
  xattrs** from emitted entries.
- **`oci-client` 0.15 exposes push** (`push_blob`/`push_manifest`); zero push
  wiring in carrick-image today. `auth::resolve_auth`'s `RegistryAuth::Basic`
  feeds push unchanged → push is genuinely small.
- **The trap guardrail is a loop bound, not a flag.** `max_traps` (default
  `1_000_000`, `runtime.rs:277`) bounds the trap loop; exhaustion returns
  `RunResult{exit_code:-1, trap_limit_hit:true}` / `TrapLimitExceeded`
  (`runtime.rs:299-311`) — **not** a clean guest exit. Build sets `max_traps`
  effectively unbounded (§7).
- **serve handlers buffer; they do not stream.** `route()` returns
  `Result<Response<Full<Bytes>>, Infallible>` and every handler returns one
  buffered body (`router.rs:56-97`). `POST /build` needs a **net-new streaming
  response path** (§10).

## 4. Architecture: a layered build pipeline

```
Dockerfile + context dir
  → parse      (instructions; ARG/ENV ${VAR} substitution; .dockerignore filter)
  → execute    (one OCI layer per filesystem-changing instruction, over a single
                persistent build scratch; host-side diff per step)
       FROM   → pull base; seed layer list + in-progress ImageConfig (carrying
                base CMD/ENTRYPOINT/ENV/USER/WORKDIR through) ; extract base into
                the build scratch; snapshot_0 = the seeded tree
       COPY   → write context files into the scratch (host-side, NO guest);
                the layer = exactly the written paths
       RUN    → re-attach the scratch (CARRICK_EXEC_OVERLAY), run argv to
                completion (no trap cap), then DIFF the scratch vs the prior
                snapshot → layer
       ENV/WORKDIR/USER/CMD/ENTRYPOINT/LABEL/EXPOSE/ARG → mutate in-progress
                config (+ history entry, empty_layer:true; no file layer)
  → assemble   (layers + config{diff_ids,history,arch,os,created} → manifest;
                compute the image id = manifest digest)
  → store&tag  (write blobs/sha256/* + config.json + manifest.json +
                carrick-image.json; tag_image)
```

**Component boundaries** (each independently testable):

| Unit | Responsibility | Depends on |
|---|---|---|
| Dockerfile parser | text → ordered `Instruction`s; ARG/ENV substitution; `.dockerignore` | pure |
| Tree differ + layer committer | (pre-snapshot, post-tree) → changed/added paths + `.wh.` for removed → a **deterministic** gzipped OCI layer + digest + diff_id | `rootfs.rs` whiteout consts + tar writer; `real_stat` |
| Build executor | drive instructions over one persistent scratch; own layer list + in-progress config; call the runtime for `RUN`, the differ for `RUN`/`COPY` | parser, differ, runtime build-attach seam, `carrick-image` |
| Image assembler + **store writer** | config.json + manifest.json + carrick-image.json serializers; manifest digest | `carrick-image` |
| Build cache | content-addressed instruction→layer reuse | store, differ keys |
| Produce verbs | `push`/`save`/`load`/`history`/`tag` | `carrick-image`, `oci-client` |
| `POST /build` (+ streaming) | unpack context, spawn `carrick build`, **stream** output | `carrick serve`, CLI |

New crate `carrick-build` (parser + differ/committer + executor + assembler +
cache); `carrick-cli` owns the `build` subcommand + produce verbs; `carrick
serve` owns `POST /build`. Dependency direction stays `cli → build → {image,
runtime} → spec`.

## 5. The core: RUN execution + host-side layer diff

Because `--fs host` gives a **merged** rootfs with **no tombstones** (§3), a layer
is computed by **diffing**, not by harvesting an upper. The mechanism:

1. **One persistent build scratch.** The executor creates a single scratch
   (the detached-container style — persisted, *not* reaped on Drop; a plain
   foreground `carrick run` reaps its `TempDir`, so build must use the persisted
   path or a new `--build-scratch <dir>` mode) and seeds it from the base image
   layers (the existing extract path). It records **`snapshot_0`** = a map of
   `path → (kind, guest mode/uid/gid via real_stat, size, content hash)` for the
   seeded tree, and the set of carrick **baseline-seed paths** (`/etc/hosts`,
   `/etc/resolv.conf`, `/etc/passwd`-class, `/tmp` perms) that `seed_guest_baseline`
   injects — these are **excluded** from every diff so they never pollute a layer.
2. **Each RUN** re-attaches the same scratch via `CARRICK_EXEC_OVERLAY` (the
   existing "re-attach an extracted overlay instead of re-extracting" path) and
   runs `/bin/sh -c "<cmd>"` (shell form) or the exec-form argv to completion with
   `max_traps` unbounded. The guest mutates the scratch in place.
3. **Diff** the scratch against the prior snapshot: a path **new or changed**
   (content hash or guest metadata differs) → a layer entry; a path **in the
   snapshot but absent now** → a `.wh.<name>` whiteout in its parent. Update the
   rolling snapshot to the current tree. (Opaque-whiteout synthesis — a dir whose
   entire contents were replaced — is **best-effort/deferred**; emitting
   per-child `.wh.` is correct, just larger.)
4. **Each COPY** writes only the context files into the scratch (host-side, no
   guest); the layer = exactly those written paths (no full diff needed). Update
   the snapshot.

**The runtime "build-attach" seam** is therefore light: *create/seed a persistent
scratch, and run a one-shot argv over it via `CARRICK_EXEC_OVERLAY` without
reaping and without a trap cap.* Both pieces exist (detached scratch persistence;
`CARRICK_EXEC_OVERLAY` re-attach) — the new work is the orchestration entry point
plus a `--build-scratch`/no-reap knob, **not** a new overlay engine. The
**execution** primitive (ELF-load, syscall dispatch, overlay attach, max-traps
threading) is genuinely reused; only the **diff** is net-new, and it is pure
host-side bookkeeping (`snapshot` walk + compare). The full-tree walk per RUN is
accepted cost for experimental v1.

(Rejected alternative: build a `MemoryBackend`-style upper-with-tombstones overlay
that can also host a fork/exec guest — true upper==diff semantics, but
`MemoryBackend::open_raw_fd → None` means that's a deep net-new overlay engine.
Deferred; the host-side diff needs no runtime overlay changes.)

## 6. Instruction handling (v1: single-stage)

Supported: `FROM`, `RUN`, `COPY`, `ENV`, `WORKDIR`, `USER`, `CMD`, `ENTRYPOINT`,
`LABEL`, `ARG`, `EXPOSE`.

- **FROM `<ref>`** — pull via `carrick-image`; seed the layer list and the
  in-progress `ImageConfig` from the base, **carrying base `CMD`/`ENTRYPOINT`/
  `ENV`/`USER`/`WORKDIR` through** unless the Dockerfile overrides them
  (`FROM` already seeds these into `ImageConfig`, `lib.rs:543-545`). Exactly one
  `FROM`; a second is a clear "multi-stage not yet supported" error.
- **RUN `<cmd>`** — shell form (`/bin/sh -c`) or exec-form argv via the §5 seam;
  non-zero guest exit fails the build with captured output; a `trap_limit_hit`/
  `TrapLimitExceeded` result is also a build failure (not silently "succeeded").
- **COPY `<src>... <dest>`** — sources resolved against the context
  (path-traversal-guarded; respects `.dockerignore`), honoring `WORKDIR`; default
  ownership root:root. `--chown`/`--from` are v1 errors. **WORKDIR is
  auto-`mkdir -p`'d** if absent (Docker semantics) and affects subsequent
  COPY/RUN cwd.
- **ENV / WORKDIR / USER / CMD / ENTRYPOINT / LABEL / EXPOSE** — mutate the
  in-progress config (env last-wins; **a new `ENTRYPOINT`/`CMD` resets the
  inherited base value**; CMD/ENTRYPOINT accept JSON (exec) or shell form). Emit a
  history entry, `empty_layer:true`, no file layer.
- **ARG** — build-time vars with `--build-arg` overrides; participate in `${VAR}`
  substitution (incl. an `ARG` before `FROM` for the image ref); **not persisted**
  to the image config (Docker semantics). Predefined proxy args accepted-and-ignored.

## 7. Experimental posture (no artificial cap)

Build is **experimental** because carrick's syscall coverage is still maturing —
**not** a designed limit:

- `RUN` runs with `max_traps` set effectively unbounded (e.g. `usize::MAX`), so a
  long `apt-get`/compile is never killed by a trap-count limit. A **wall-clock
  timeout** MAY bound a hung step (liveness guardrail). `trap_limit_hit` must
  still be checked and mapped to a build failure.
- A missing syscall behaves like the rest of carrick (ENOSYS-by-name; mostly
  tolerated). A `RUN` that fails on a missing/incorrect syscall is a **tracked
  carrick coverage bug**, not an accepted ceiling.
- Success is defined against a **growing Dockerfile corpus** (§11), starting
  simple. No claim that "every Hub Dockerfile builds."

## 8. The differ + layer committer (the inverse of `rootfs.rs::apply`)

Input: a diff result — the set of added/changed paths (each with guest-visible
metadata) + the set of removed paths. Output: a gzipped tar layer blob + its
**registry digest** (over compressed bytes) + its **diff_id** (over the
*uncompressed* tar, for `config.rootfs.diff_ids`).

Rules (mirroring the OCI conventions `rootfs.rs` already applies):
- Each added/changed file/dir/symlink → a tar entry. **Metadata is read via the
  xattr-aware `real_stat`/`fd_carrick_meta`** (guest mode/uid/gid in
  `user.carrick.*`), *not* the raw on-disk POSIX bits; **all `user.carrick.*`
  xattrs are stripped** from emitted entries; `user.carrick.socket` markers are
  skipped (as `rootfs.rs` skips special nodes).
- Each removed path → a `.wh.<name>` whiteout entry (reuse `WHITEOUT_PREFIX`).
- **Determinism (hard requirement for the cache, §9):** entries sorted by path;
  **mtime normalized to a fixed constant (0)** — *not* the scratch's wall-clock
  mtime, which would differ every run and break cache bit-identity; deterministic
  uid/gid; no PAX time extensions; fixed gzip level. gzip-header determinism is
  free with flate2's `GzEncoder` (mtime defaults 0, OS byte 255); the residual
  risk is the **tar header**, which these rules pin.
- A metadata-only step → an **empty layer** (`empty_layer:true` in history), like
  Docker.

**Round-trip test (M0), corrected:** commit a synthesized diff to a blob, then
compose `RootFs::from_layer_paths([..base, committed_blob])` (the **public** API
`rootfs.rs:379`; `apply_layer` is private) and assert the resulting tree matches.
Fidelity ceiling: `RootFsMetadata` exposes only path/kind/mode/size
(`rootfs.rs:166-172`), so the round-trip asserts **path/kind/contents/file-mode**.
To verify **uid/gid/mtime/whiteout** fidelity, extract the blob via
`extract_layer_paths_to_dir` into a cap-std dir and `real_stat` it. M0 also
**defines the upper-scratch/diff data contract** (added set + removed set +
per-entry metadata source) that M1's seam must emit.

## 9. Store write path (net-new) + image assembler

Building an image requires three serializers the store lacks today (it only ever
*pulls*):

1. **`ImageConfig` → OCI `config.json`** (PascalCase) including
   `rootfs.diff_ids`, `history`, `architecture` (guest arch), `os` (`linux`),
   `created`, and the runtime `Config` block. (`resolve()` round-trips **none** of
   the first five — §3.)
2. **`OciImageManifest` builder** (schemaVersion 2, config descriptor + ordered
   layer descriptors) + **manifest-digest computation** → the **image id**.
3. **`PullSummary` (`carrick-image.json`) writer** — ordered layer digests/
   sizes/paths + image digest + canonical ref — because `resolve`/`tag`/`list`
   key on it; without it, `carrick run t1` (bare `-t t1` normalizes to
   `docker.io/library/t1:latest`) would try to pull from docker.io.

The assembler **always writes a full `manifest.json`** (config + layer
descriptors), `config.json`, and `carrick-image.json`, plus the layer blobs (and
the config blob — see §10 save), then `tag_image`. This is the same on-disk shape
a pull produces, so a built image is immediately resolvable/runnable/taggable.

## 10. Build cache + produce verbs

**Build cache** (content-addressed): `key = sha256(parent_key ‖ instruction_text
‖ extra)`; `extra` for COPY/ADD = content hash of the copied files (path+mode+
bytes), for RUN = empty (Docker caches RUN on instruction text + parent only). On
a hit, reuse the blob, print `---> Using cache`; the first miss busts the cache
for all subsequent instructions. `--no-cache` disables lookups; `--pull` re-pulls
the base. Cache **correctness depends on the deterministic committer (§8)** — a
hit must produce a bit-identical layer to a miss. Cache blobs are ordinary store
blobs, reclaimed by the existing `gc_blobs`/`system prune`.

**Produce verbs:**
- **`push`** — wire `oci-client` `push_blob`/`push_manifest`; reuse
  `auth::resolve_auth` (`Basic` feeds push unchanged). Streams `Pushed`/`already
  exists`.
- **`save`/`load`** — docker-archive (`manifest.json`+`repositories`+per-layer
  `layer.tar`, `RepoTags` from `PullSummary.image`) and OCI-layout
  (`oci-layout`+`index.json`). Note: OCI-layout save must **materialize the config
  as a content-addressed blob** in `blobs/sha256/` (today it's stored as the image
  dir's `config.json`, `lib.rs:416`, not a blob) and synthesize `oci-layout`/
  `index.json` (which carrick doesn't keep); docker-archive must translate the OCI
  manifest into the docker-archive schema. A `save`/`push` of a *pulled* image
  lacking `manifest.json` must recompute the config digest from `config.json`
  bytes (`resolve` tolerates a missing manifest, `lib.rs:596`; built images always
  have one per §9).
- **`history`** — render from the **raw `config.json` bytes** (e.g.
  `oci_client::config::ConfigFile`), **not** the `resolve()`-flattened
  `ImageConfig` (which drops `history`). For carrick-built images, §9 ensures the
  config carries a complete `history` array.
- **`tag`** — exists (`tag_image`, `lib.rs:804`); ensure built images tag cleanly.

## 11. `POST /build` in `carrick serve` (with net-new streaming)

The legacy (pre-BuildKit) builder protocol: the request body is the gzipped
context tar (Dockerfile inside, named via `?dockerfile=`; `?t=` may **repeat** for
multiple tags; `?buildargs=`/`?labels=` arrive as **URL-encoded JSON**;
`?nocache=`/`?pull=`). The handler unpacks the context to a temp dir and **shells
out to `carrick build`** (the server-as-translator pattern; keeps the
no-tokio-before-fork invariant — the build's guest forks happen in the spawned
process). It streams the child's progress as protocol NDJSON: `{"stream":"..."}`,
`{"aux":{"ID":"sha256:..."}}`, `{"errorDetail":{"message":"..."}}`.

**Streaming is net-new in serve.** Today `route()` returns a single buffered
`Full<Bytes>` (`router.rs:56-97`); `/build` must use a **streaming response body**
(`StreamBody`/`BoxBody` + a channel pumping the child's stdout, `Transfer-Encoding:
chunked`). hyper 1.9 + http-body-util 0.1 support this; the route signature/body
type changes for this endpoint. The **request** side is fine (`BodyExt::collect`
already buffers the whole context tar). The **query parser** also needs its own
handling — the existing `query_param` (`router.rs:32-37`) does a single
`split_once('=')` with no URL-decoding and returns the first match only, so it
can't handle repeated `?t=` or encoded JSON.

This makes `DOCKER_BUILDKIT=0 docker -H unix://…/carrick.sock build -t app .` and
compose `build:` work for **legacy-builder** clients. BuildKit-default clients are
out of scope.

## 12. Milestones

### M0 — Differ + layer committer (no guest)
The host-side differ (snapshot vs post-tree → added/removed sets) + the
deterministic committer (§8): added/changed entries + `.wh.` whiteouts, sorted,
mtime=0, xattr-stripped. Define the diff data contract M1 emits.
**Exit:** round-trip via `RootFs::from_layer_paths([..base, blob])` asserts
path/kind/contents/file-mode; an `extract+real_stat` check asserts uid/gid + that
a removed path becomes a `.wh.`; identical diffs yield **identical digests**
(determinism).

### M1 — `carrick build` single-stage engine
Dockerfile parser (+ `.dockerignore`, ARG/ENV substitution, shell/exec forms);
the §5 build-attach seam (persistent scratch seeded from base, per-RUN re-attach
via `CARRICK_EXEC_OVERLAY`, no reap, `max_traps` unbounded, snapshot+diff);
COPY/metadata first, then RUN; the §9 store write path (config/manifest/
PullSummary serializers + manifest digest); `tag`.
**Exit:** `carrick build -t t1 .` on a COPY+metadata Dockerfile (static
`linux-aarch64-hello` fixture) → `carrick run t1` executes it; a `RUN`-bearing
Dockerfile (`RUN echo hi > /f`; coreutils) builds, the new layer contains exactly
`/f` (not the whole rootfs), and a `RUN rm <basefile>` produces a `.wh.`; a
failing `RUN` (non-zero or trap-limit) fails the build with captured output.

### M2 — Produce verbs
`push` (oci-client), `save`/`load` (docker-archive + OCI-layout incl. config-blob
materialization), `history` (raw config bytes).
**Exit:** `build → push` to a local registry then `pull`+`run`; `save`→`load`
round-trips; `docker load` accepts a `carrick save` tarball (and vice-versa) for a
simple image; `history` renders the built image's layers.

### M3 — Build cache + `POST /build`
Content-addressed cache (§10) with `--no-cache`; streaming `POST /build` in serve.
**Exit:** a second `build` of an unchanged Dockerfile reuses cached layers (no
`RUN` re-executed, bit-identical digests); `DOCKER_BUILDKIT=0 docker -H
unix://…/carrick.sock build -t app .` builds a simple image end-to-end (streamed
output); a small Dockerfile-corpus matrix (COPY+static-bin, RUN-coreutils,
ENV/WORKDIR/USER/CMD, a delete→`.wh.` case) published green vs `docker build`.

## 13. Acceptance rules

1. The committer is proven by **round-trip** (M0), not by eyeballing tar output;
   the round-trip uses the **public** `from_layer_paths` and an `extract+real_stat`
   check for uid/gid/whiteout (the in-memory `RootFsMetadata` alone can't verify
   ownership/mtime).
2. No `RUN` is killed by a syscall/trap cap; a `RUN` failure is a real non-zero
   exit, a `trap_limit_hit`, or a **filed** carrick coverage bug — never hidden.
3. Built images are byte-validated runnable (`carrick run` the result); where a
   `docker build` oracle exists, the produced rootfs/layers are compared.
4. Cache correctness before speed: a hit produces a **bit-identical** layer to a
   miss (guaranteed by the deterministic committer, §8 — mtime=0, sorted, fixed
   gzip).
5. `POST /build` reuses the `carrick build` engine via subprocess (no second build
   implementation, no guest fork in the server's tokio runtime), and adds a
   streaming response body (a new serve capability, not a reuse of the buffered
   handlers).

## 14. Non-goals

- **BuildKit / buildx / LLB** — v1 targets the legacy builder
  (`DOCKER_BUILDKIT=0`) only. Permanent for this spec.
- **Multi-stage** (`FROM … AS`, `COPY --from=`) — v2; a second `FROM` errors.
- **`ADD` from URL / auto-extract, `COPY --chown`/`--from`, `RUN --mount`,
  `ONBUILD`/`HEALTHCHECK`/`SHELL`/`VOLUME`/`STOPSIGNAL`** — v2+.
- **Opaque-whiteout optimization** — v1 emits per-child `.wh.` (correct, larger).
- **Cross-arch build** — produces an image for carrick's guest arch.
- **Reproducible builds beyond deterministic layer digests** — best-effort. (Note:
  deterministic *digests* are NOT best-effort; they are the §8/§13.4 hard
  requirement the cache depends on.)

## 15. Risks & open questions

- **The §5 build-attach seam** is the load-bearing unknown — persisting the build
  scratch across steps (no reap) and re-attaching it per RUN via
  `CARRICK_EXEC_OVERLAY` without re-extraction. M1 spikes this first. It is
  lighter than a new overlay engine (both pieces exist) but the no-reap +
  one-shot-over-attached-scratch entry point is new.
- **Diff cost & fidelity.** A full-tree snapshot+walk per RUN is O(tree); fine for
  experimental v1. Fidelity: v1 handles mode + uid/gid (xattr-aware) + emits
  mtime=0; **xattrs/hardlinks are best-effort**, flagged if a corpus image needs
  them. Opaque whiteouts deferred (per-child `.wh.` instead).
- **`RUN` coverage** — broad-syscall RUNs (apt/compilers) will surface coverage
  bugs; expected, feeds the conformance backlog.
- **`save`/`load` Docker interop** — docker-archive has version nuances; M2
  validates cross-tool round-trip for a simple image and documents divergence.
- **Cache-key parity with Docker** is explicitly **not** a goal — carrick's cache
  is internally correct (deterministic), keys need not match Docker's.

## Appendix — code anchors (verified 2026-06-06)

- Store OCI-shaped, `PullSummary`/`carrick-image.json` is the resolve/tag/list key,
  lossy `resolve`: `carrick-image/src/lib.rs:166,416-417,527-557,577-588,657,
  698,753,804-828`. Push auth: `auth.rs` (`resolve_auth`→`Basic`). `oci-client`
  0.15 push: unwired.
- Whiteout consts (module-private) + apply (read) direction + public compose API +
  test-only tar writer: `rootfs.rs:95-96,166-172,213,320-336,379,546,650,874`.
- `--fs host` is a merged rootfs; no deletion tombstones; xattr metadata:
  `fs_backend.rs:984-998,1403,1542-1570,1573,1664,2321-2330,2383-2388,3062`.
  Memory-only tombstone + `open_raw_fd→None`: `fs_backend.rs:537,663-671,728-733`.
- Trap guardrail (loop bound; `TrapLimitExceeded`): `runtime.rs:277,299-311`.
- Detached scratch persistence + `CARRICK_EXEC_OVERLAY` re-attach:
  `crates/carrick-cli/src/lifecycle.rs` (run_supervised_child / exec),
  `execute.rs:203-223,236-242`.
- serve buffers (no streaming) + `query_param` limits:
  `crates/carrick-cli/src/serve/router.rs:32-37,56-97`; subprocess pattern:
  `serve/spawn.rs`.
