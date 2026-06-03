# Docker-Compatible Frontend: Audit & Ship Roadmap

**Scope:** the `carrick` CLI surface that mimics the docker CLI — commands, flags,
output, exit codes, lifecycle, image management, networking/volumes, isolation
knobs, and any daemon/API surface. **Not** the HVF/syscall runtime internals.

**Status:** audit complete; roadmap proposed, not yet executed.
**Audited against:** `main` @ `1984878` (2026-06-01).
**Method:** 7-dimension parallel audit, every claim adversarially re-verified
against the source (135 code-substantiated findings) + a completeness critique.
See [Appendix A](#appendix-a--methodology).

**Maintainer decisions baked into this doc** ([Decisions](#4-decisions)):
1. **Posture** — ship an *explicitly documented docker-CLI subset* for
   single-container, host-networked workloads; scope the README's
   "production-ready" claim to the **runtime**, and publish a `COMPAT.md` matrix.
2. **Unsupported-flag policy** — **hybrid**: hard-error flags with
   correctness/security implications (a non-identity `-p` map); warn-and-accept
   the merely-unenforceable (`--memory`, `--privileged`, `--cap-*`).
3. **docker.sock / API shim** — **undecided**, tracked as an
   [open question](#7-open-questions).

---

## 1. Where the frontend stands

Carrick's Docker-compatible frontend is a **credible podman-style single-container
runner wrapped in a CLI that diverges from docker on the highest-traffic
defaults.**

**Genuinely strong, shipped surface:**

- **Daemonless lifecycle** — `run -d` + `ps`/`stop`/`kill`/`rm` over an on-disk
  registry (`crates/carrick-runtime/src/container.rs`), with full-id / 12-hex
  short-id / unambiguous-prefix / name resolution behind a path-traversal guard
  (`container.rs:221-248`), correct `SIGTERM`→grace→`SIGKILL` stop
  (`lifecycle.rs:220-233`), `--rm` reaping, and stale-state reconciliation in
  `ps` (`container.rs:286-292`). Podman-shaped, not docker-daemon-shaped — and
  that is a deliberate design choice (`lifecycle.rs:5`, "There is no carrickd").
- **OCI pull/store** — content-addressed blobs with dedup, and well-tested
  multi-arch `--platform` selection (`crates/carrick-image/src/lib.rs`).
- **Interactive `-it` pty path** — the most docker-faithful path
  (`execute.rs:462-471`): real pty allocation, exit-code passthrough.

**The problem:** it is **not** docker-compatible as a CLI, and it is nowhere near
socket/API-compatible. `bollard` (the Docker API client) appears **only as a
test-time oracle** in `conformance.rs` — carrick serves no API. The README's
"fully functional and production-ready" (`README.md:8`) is defensible for the
*runtime* it describes (sockets, pts, `apt-get`, `python3 -m http.server`
end-to-end) but is **not** defensible as a docker-CLI claim: a tool whose default
`run` exits 0 on failure, prints a JSON envelope to stdout, silently ignores
`-u`/`-p`, and cannot `logs`/`exec`/`inspect` is not a drop-in docker.

---

## 2. Compatibility matrix

Legend: ✅ present · 🟡 partial · ⛔ parsed-but-ignored (silent no-op) · ↔ divergent · ❌ missing · 🚫 non-goal

### 2.1 Commands

| Command | Status | Notes |
|---|---|---|
| `run` | 🟡 | Works, but the **default** path is not docker-shaped — see [§3.1](#31--blocker--the-default-run-path). `-t/-i/-d` good. |
| `pull` | 🟡 | Anonymous only; always re-downloads; JSON output not progress stream. |
| `ps` | 🟡 | Diverges on columns/status/flags — [§3.5](#35--output--errors-not-docker-shaped). |
| `stop` | ✅ | `SIGTERM`→grace→`SIGKILL`; `-t`. Echoes the resolved id (docker echoes the typed arg). |
| `kill` | ✅ | `-s/--signal`, default `KILL`. |
| `rm` | 🟡 | `-f` works; `-v/--volumes`, `-l/--link` missing. |
| `shell` | ✅ | carrick convenience (interactive `/bin/sh`); not a docker command. |
| `exec` | ❌ | Hard `bail!("not implemented")` (`commands.rs:356`). |
| `logs` | ❌ | Output **is** captured to `output.log` but nothing reads it (dead `_logs_marker` stub, `lifecycle.rs:338-343`). |
| `inspect` | ❌ | Registry already persists JSON state; not surfaced. |
| `wait` | ❌ | `pid_alive` + persisted `exit_code` primitives exist. |
| `start` / `create` | ❌ | `run` fuses create+run in the fork; a container can never be (re)started. |
| `restart` | ❌ | Depends on `start`. |
| `images` / `rmi` / `prune` | ❌ | Store is **write-only** — grows unbounded; only fix is `rm -rf ~/.carrick`. |
| `tag` | ❌ | Store is tag-keyed dirs; no alias layer. |
| `login` / `logout` | ❌ | No credential surface; blocks all private/authenticated images. |
| `attach`, `cp`, `commit`, `rename`, `top`, `stats`, `port`, `diff`, `export`, `update`, `pause`/`unpause`, `events`, `version`/`info`, `system df`/`prune` | ❌ | Not implemented. |
| `build` / `push` / `compose` | 🚫 | Non-goals (carrick is an OCI **consumer**). |
| Docker Engine REST API (`/var/run/docker.sock`) | 🚫\* | No `UnixListener`/HTTP server. \*Posture undecided — [open question](#7-open-questions). |

### 2.2 `docker run` flags

| Flag | Status | Notes |
|---|---|---|
| `-t/--tty`, `-i/--interactive`, `-d/--detach` | ✅ | The faithful paths. |
| `--platform` | ✅ | Multi-arch select; amd64 ⇒ Rosetta. |
| `-w/--workdir` | ✅ | Overrides image WORKDIR, falls back correctly. |
| `-v/--volume` | 🟡 | Bind `HOST:CONTAINER[:ro|rw]` works; **named/anon volumes treated as host paths**; no `:z/:Z/:cached/:delegated`. |
| `--mount` | 🟡 | Bind only; `type=` is **dropped** (`runtime_util.rs:53`) so `type=tmpfs/volume` mis-parse as binds and error. |
| `--entrypoint` | 🟡 | Single token only; `--entrypoint ''` yields an empty `argv[0]` instead of **clearing** (`commands.rs:265`). |
| `-e/--env`, `--env-file` | 🟡 | `KEY=VAL` works; **bare `-e KEY` host-import is dropped** (`lib.rs:101`); `--env-file` is `Option` (docker allows repeats). |
| `--rm`, `--name` | 🟡 | Honored **only on the detached path**; foreground `run --name` silently discards; no uniqueness check even on `-d`. |
| `--pid` | 🟡 | `private`/`host` wired (`execute.rs:111-113`); `container:<id>` is a clap parse error. |
| `-u/--user` | ⛔ | **Computed into `_user` and discarded** (`lib.rs:120`); `RunSpec` has no uid/gid; guest creds hardcoded 0/0 (`creds.rs:62-69`). Also swallows image `USER`. |
| `-p/--publish` | ⛔ | Destructured `publish: _` and dropped (`commands.rs:236`). |
| `--expose` / `-P` | ⛔ | Parsed/ignored. |
| env vs image ENV precedence | ✅\* | Correct per-key last-wins; \*carrick injects extra baseline defaults (`TERM/LANG/LC_ALL/DEBIAN_FRONTEND/PAGER`, `lib.rs:87-91`) — documented, not a bug. |
| `--hostname/-h`, `--add-host` | ❌ | UTS identity / `/etc/hosts` injection. |
| `--read-only`, `--tmpfs` | ❌ | No RO-root field; tmpfs mis-parses (see `--mount`). |
| `--network/--dns/--link` | ❌ | Host-only model; see [§3.6](#36--architectural-mostly-non-goals). |
| `--memory/--cpus/--pids-limit/--ulimit/--cpu-*` | ❌ | No cgroups under HVF. |
| `--cap-add/--cap-drop/--privileged/--security-opt/--device/--sysctl/--group-add` | ❌ | No Linux LSM/device model to map onto. |
| `--restart`, `--stop-signal`, `--stop-timeout`, `--init` | ❌ | — |
| `--label/-l`, `--cidfile`, `--sig-proxy`, `--detach-keys`, `--health-*`, `--log-driver`, `--gpus`, `--runtime`, `--userns`, `--ipc`, `--uts`, `--volumes-from`, `--annotation`, `--mac-address`, `--domainname` | ❌ | Long tail. |

---

## 3. Verified gaps, by theme

Every claim below was re-checked against the cited source.

### 3.1 🔴 BLOCKER — the default `run` path

The single most damaging fact in this audit. With no `-t/-i/-d/--raw`, output
**does** stream live and byte-exact and streams **are** separated
(`fs.rs:1358-1369`), but `commands.rs:320-339` then:

1. **appends a multi-line JSON envelope** to stdout (with always-empty
   `stdout`/`stderr` fields, since the bytes already streamed), and
2. **never calls `process::exit`** — so the host exit code is **always 0**
   regardless of the container's real code (only the tty/raw branches at
   `commands.rs:305-318` exit correctly; `main` returns `Ok`).

Consequences a docker user or wrapping script hits immediately:
- `carrick run img false; echo $?` prints **0** (inverse of docker) → breaks
  `&&`-chains, CI gates, Make.
- `OUT=$(carrick run img echo hi)` captures `hi` **plus a JSON blob**.
- On trap-limit the default path prints a large JSON compat-report to stdout
  **then** bails to exit 1 — a non-docker dual-output shape (`commands.rs:334-338`).

The fix is contained: on the default branch, drop the envelope (gate JSON behind
an explicit `--json`), and `process::exit(result.exit_code)` like tty/raw already do.

### 3.2 🟠 Silently-ignored advertised flags (no-ops that look like they worked)

- **`-u/--user`** — discarded (`lib.rs:120`). `run -u 1000` runs as **root**. A
  privilege-drop / file-ownership / security divergence that also swallows the
  image's `USER`. *Effort medium*, not large: the setuid/setgid syscall plumbing
  already exists in `dispatch/creds.rs`; the gap is a `RunSpec` uid/gid field +
  initial-cred wiring + `uid[:gid]`/`user[:group]` parsing.
- **`-p/--publish`** — dropped (`commands.rs:236`). Under host-only networking a
  *non-identity* map can never work; per the hybrid policy it should **hard-error**.
- **`--entrypoint ''`** — empty `argv[0]` instead of clearing.
- **bare `-e KEY` / env-file bare KEY** — dropped instead of importing the host value.
- **`--mount type=`** — ignored, so `type=tmpfs/volume` mis-parse as binds and error.

### 3.3 🟠 Missing connective lifecycle verbs

The verbs that make `-d` usable are absent: **`logs`** (output captured but
unreadable), **`exec`** (hard bail), **`inspect`**, **`wait`**,
**`start`/`create`**. Without them a detached container is a black box.

### 3.4 🟠 Image management is download-only

No **`images`** (can't see what you pulled), no **`rmi`/`prune`** (disk-fill
hazard), no **`tag`**, and **`RegistryAuth::Anonymous` unconditionally**
(`image/lib.rs:269`) — every private / GHCR / ECR / authenticated-Hub image is
unreachable and anonymous Hub hits rate limits with no remedy. Pull always
re-downloads (no cache short-circuit) and prints `serde_json`, not docker's
progress/`Status:` stream.

### 3.5 🟡 Output & errors not docker-shaped

`ps` emits `CONTAINER ID / IMAGE / STATUS / PID / NAMES` (`lifecycle.rs:153-156`):
omits `COMMAND/CREATED/PORTS`, adds a non-docker `PID` column, lowercase
`running`/`exited (N)` vs docker `Up …`/`Exited (N) … ago`, blank `NAMES` (no
auto-name), only `-a/-q` (no `--format/--filter/--no-trunc`). Errors print anyhow
`Debug` + exit 1 — never docker's `125/126/127` or `Error response from daemon`;
the image-not-found path lacks docker's `Unable to find image … locally` + `125`.

### 3.6 🟡 Architectural (mostly non-goals)

Networking is **host-only** — `NamespaceMode` has only a `Host` variant
(`spec/lib.rs:99-102`); port **remap** can never work under socket-translation
(`-p` "works" only when host==container port because the listener is already on
the host port). `NamespaceConfig` models six namespaces but is **dead code**
(constructed nowhere, all `Host`). Resource/cap/security knobs are absent (no
cgroups / LSM under HVF). No daemon API (compose/testcontainers/IDE integrations
cannot work).

---

## 4. Decisions

### 4.1 Posture — documented docker-CLI subset

Ship as an **explicitly documented "docker-CLI subset for single-container,
host-networked workloads on Apple Silicon"** — a podman-style drop-in for
`run/pull/ps/stop/kill/rm/logs/exec/inspect`, **not** a docker socket/API
implementation and **not** an unqualified `alias docker=carrick`. A genuine
single-container `alias docker=carrick` becomes honest only after P1+P2 land.

- Scope the README claim: *"production-ready Linux binary **runtime**; docker-CLI
  compatibility is an evolving subset — see `COMPAT.md`."*
- Publish the [§2 matrix](#2-compatibility-matrix) as `COMPAT.md`, stating
  host-only networking, no port remap, no build/compose/socket as **permanent**
  constraints (not "coming soon").

### 4.2 Unsupported-flag policy — hybrid

| Class | Behavior | Examples |
|---|---|---|
| Correctness / security implication | **Hard-error** with a clear message | non-identity `-p` map, malformed `-p`/`-v` |
| Merely unenforceable under HVF | **Warn-and-accept** (no-op + one-line stderr warning) | `--memory`, `--cpus`, `--privileged`, `--cap-*`, `--security-opt` |
| Has a feasible emulation | Implement (see roadmap) | `--user`, `--hostname`, `--ulimit`, `--read-only`, `--tmpfs` |

Rationale: a silent no-op is the worst outcome (looks like it worked); a hard
error on a flag that *can* work in a degraded way (`--memory`) needlessly breaks
copy-pasted run lines. The split keeps invocation compatibility while never lying
about correctness.

---

## 5. Roadmap

Sequenced by dependency and user-visible value. Effort: small / medium / large /
xlarge. Corrections from the completeness critic are applied (duplicate ratings
collapsed; four bad dependencies removed; orphaned gaps scheduled; per-phase
differential-test exit criteria added).

### P0 — Quick wins (ship first; all small)

The blocker fix plus the highest value-per-effort items. No new subsystems.

- **Propagate the container exit code on the default `run` path** — replicate the
  tty/raw `process::exit` (`commands.rs:305-318`) on the default branch
  (`commands.rs:320-339`). *Kills exit-0-on-failure.*
- **Drop the trailing JSON envelope** from the default path; gate it behind
  `--json`. *Cleans `$(...)`.*
- **`carrick logs <id> [-f] [--tail N]`** — capture already exists; replace the
  dead `_logs_marker` stub. *Unblocks the entire `-d` workflow.*
- **Enforce `--name` uniqueness on `run -d`/`create`** — scan `container::list()`
  before `state.create()` (`lifecycle.rs:50`); docker-style `Conflict` error.
- **Honor bare `-e KEY` / env-file bare KEY** host-import (`lib.rs:101`).
- **Validate/reject `-p`** instead of dropping it (hybrid policy): non-identity
  or malformed maps hard-error.
- **Fix `--entrypoint ''`** to clear the entrypoint.

### P1 — Make default `run` behave like `docker run`

**Goal:** `carrick run alpine cmd` (no flags) gives docker-shaped behavior: clean
streamed stdio, the real exit code, no surprise JSON.

- Map docker exit-code conventions: `127` not-found, `126` not-executable, `125`
  engine error incl. the `Unable to find image … locally` path *(depends: exit-code propagation)*.
- Send the trap-limit report to stderr / `--json` only *(depends: envelope removal)*.
- **Migrate all internal consumers of the run JSON envelope** to `--json`
  (`run-elf` emits the same envelope, `commands.rs:187-199`; conformance fixtures).
- **Extend conformance** with a non-`--raw` differential case asserting stdout
  cleanliness, stream separation, and exit-code parity vs the bollard oracle
  (today it only runs `--raw`, merges streams, and skips exit asserts —
  `conformance.rs:291,326-327,370`).

**Exit:** `OUT=$(carrick run alpine echo hi)` is exactly `hi`; `run alpine false;
echo $?` → 1; conformance asserts default-path separation **and** exit-code
parity for a command corpus; no internal envelope consumer remains on stdout.

### P2 — Honor or honestly reject every parsed flag + registry auth

**Goal:** every advertised flag does what docker does or fails per the hybrid policy.

- **Wire `--user`/image `USER`** to the runtime — `RunSpec` uid/gid + initial
  creds (plumbing exists in `dispatch/creds.rs`); parse `uid[:gid]`/`user[:group]`.
- Fix env import; **`--env-file` repeatable** (`Option<PathBuf>`→`Vec`).
- **Accept-and-warn `:z/:Z/:cached/:delegated`** mount modes (treat as `rw`).
- **Registry auth** *(hoisted from P5 — it gates "can I run my company's image")*:
  read `~/.docker/config.json` / `DOCKER_CONFIG`, Basic/Bearer + cred helpers.
- **`carrick login` / `logout`** *(depends: auth reader)*.
- Standardized **hybrid** handling for unsupported isolation/limit flags
  (hard-error correctness, warn-and-accept the rest) — replaces opaque clap parse
  failures and silent drops.

**Exit:** `run -u 1000:1000 alpine id` reports uid=1000 gid=1000 and an image with
`USER 1000` runs as 1000; `-e HOME` imports the host value; a GHCR image pulls
after `login`; `--entrypoint ''` clears; `-v x:/y:cached` runs with a warning;
every unsupported flag follows the documented hybrid policy (no silent no-op).

### P3 — Make the detached lifecycle observable/operable

**Goal:** a `run -d` container is as inspectable/operable as a docker one.

- **`carrick wait <id>`** — `pid_alive` poll + persisted `exit_code`.
- **Minimal `carrick inspect <id>`** with `-f/--format` — surface the persisted
  `ContainerState` as a docker-shaped array (`.Id/.Name/.State.Status/.State.ExitCode/.State.Pid`).
- **`carrick exec [-i] [-t] [-u] [-w] [-e] <container> <cmd>`** — re-model the
  arg shape (today `context+command`, `args.rs:206-210`), resolve via
  `container::resolve`, spawn into the running container with stdio + exit-code
  passthrough. *Independent of `inspect` — the critic flagged the original
  exec→inspect dependency as wrong.*
- **Reconcile-and-persist stale state** — write back `Exited` + best-effort
  code/`FinishedAt` (today `reconciled_status` is read-only in `ps`,
  `container.rs:286-292`, so a crashed container reports a possibly-wrong code).

**Exit:** `run -d --name web nginx && logs web` shows output; a duplicate
`--name web` is rejected; `wait web` returns the code; `inspect web -f
'{{.State.Status}}'` works; `exec -it web sh` opens an interactive shell with
correct exit-code passthrough; ps/inspect/wait agree after a crash; **a
conformance case covers each new verb.**

### P4 — docker-shaped output & image visibility

**Goal:** output/format and the pull→inspect→clean loop are docker-recognizable;
the store stops being write-only.

- **Rework `ps`** — add `COMMAND` (stored `container.rs:43-44`), relative
  `CREATED`, docker `STATUS` strings, auto-generated `NAMES`, `--format` +
  `--no-trunc` + basic `--filter`. *(No `inspect` dependency — ps already has the
  data.)*
- **`carrick images` / `image ls`** — walk the store layout; REPOSITORY/TAG/ID/SIZE.
- **`carrick rmi` / `image prune`** *(depends: images)* — ref/id removal +
  unreferenced-blob GC.
- **`carrick tag`** *(depends: images)* — cheap ref alias.
- **`--pull always|missing|never` policy + cache short-circuit** + docker-shaped
  pull output (progress/`Status:`; skip re-download when present). *(Schedules the
  orphaned `--pull` finding.)*
- **`carrick system df` / `system prune`** — the daemonless disk-fill cleanup story.
- **docker-shaped CLI error phrasing**, stderr-only routing.

**Exit:** `--format '{{.Names}}'` works against `ps`; `images`/`rmi`/`prune`/`tag`
manage the store; repeated `pull` says cached; errors go to stderr with
docker-recognizable text; **conformance covers `images`/`rmi`/`ps --format`.**

### P5 — start/create/restart depth

**Goal:** the create/start/restart decomposition prepared containers expect.

- **Persist the full `RunSpec`** (env/mounts/workdir/user/entrypoint) in the
  registry — *the real prerequisite for relaunch; the critic flagged the original
  ordering (persist-config depending on start) as inverted.*
- **Decouple create from run** *(depends: persist RunSpec; reconciled state)* —
  `create` (build+persist, print id) + `start` (relaunch supervisor). Note:
  daemonless `restart` is stop+recreate (no live process to resume) — confirm
  acceptable via the [open question](#7-open-questions).
- **`carrick restart [-t]`** *(depends: start)*.
- **`--stop-signal`/`--stop-timeout` + image `STOPSIGNAL`** *(depends: persist
  RunSpec)* — today stop is hard-coded `SIGTERM`→`SIGKILL` (`lifecycle.rs:220-233`).

**Exit:** `create --name x img && start x && restart x` work; `stop x` honors the
image `STOPSIGNAL` / per-container `--stop-signal`; **conformance covers
create/start/restart.**

### P6 — best-effort isolation under HVF

**Goal:** the subset of isolation/limit flags the HVF/syscall model can emulate;
accept-or-reject the rest per the hybrid policy.

- **`--read-only`** + real **`--tmpfs` / `--mount type=tmpfs`** (RO-root field +
  a real tmpfs mount type at the VFS layer; today `type=` is dropped).
- **`--hostname/-h` + `--add-host`** — thread a hostname into `uname`/`gethostname`
  and inject `/etc/hosts` entries (feasible without a real UTS namespace;
  `/etc/hosts` is synthesized today, `fs_setup.rs:112-139`).
- **`--ulimit`** — seed per-container rlimits (the layer emulates `prlimit64`; no
  CLI seeds it).
- **`--pid=container:<id>`** — join a running container's pid ns via its recorded
  `init_pid` (`container.rs:51`). *Independent of create/start — the critic
  flagged the original dependency as over-constrained.*
- **`--memory/--cpus`** — best-effort VM sizing / accounting **or** documented
  warn-and-accept no-op (decide via the [open question](#7-open-questions);
  `CARRICK_EXPOSED_CPUS` already shapes perceived nproc, `args.rs:67`).

**Exit:** `run --read-only --tmpfs /run --hostname web --add-host db:10.0.0.5
--ulimit nofile=65535 img` runs with those semantics observable in the guest;
`--pid=container:<id>` joins; `--memory/--cpus` enforce a documented best-effort
cap or are an explicit warned no-op.

---

## 6. Non-goals

Deliberately **not** chased (document as permanent constraints, not "coming soon"):

- **Docker Engine REST API** over `/var/run/docker.sock` (unless the
  [open question](#7-open-questions) reopens it) — contradicts the daemonless design.
- **`docker compose` / multi-container orchestration** — needs bridge networking
  + the daemon API.
- **`docker build` / Dockerfile / BuildKit / buildx / push** — carrick is an OCI
  **consumer**. (`tag`/`save`/`load` are cheaper and stay in scope.)
- **Bridge/custom/none/container networking, per-container IPs, inter-container
  DNS, `--link`, `-p` NAT** — incompatible with direct host-socket translation;
  port **remap** can never work.
- **Full cgroup enforcement** (`--memory` hard caps, `--cpu-quota`, `--pids-limit`,
  `--blkio`) — no cgroups under HVF; at most best-effort (P6).
- **Enforced Linux capabilities / seccomp / apparmor / SELinux / `--privileged` /
  `--device` passthrough** — no LSM/device model to map onto; accept-or-reject
  for invocation compatibility only.
- **`docker events` / `stats` / `pause`-`unpause` / GPU / `--runtime` /
  log-drivers** — daemon/cgroup-dependent, low single-container value.
- **Byte-identical container env** — carrick injects extra baseline defaults;
  keep per-key precedence correct, don't chase byte-identity.
- **Repurposing `carrick volume`** to mean docker named volumes — it is
  APFS-subvolume management (`apfs.rs`). **Rename/namespace it** to remove the
  collision (e.g. `carrick scratch` or `carrick volume --apfs`).

---

## 7. Open questions

1. **docker.sock shim** *(deferred — flagged)*: is a thin, read-mostly shim
   (`/_ping` + `/version` + `/info` + `/containers/json` + `/images/json`) ever in
   scope to unlock testcontainers / IDE container discovery, or is
   daemonless-forever a hard product rule? The single biggest ecosystem lever and
   the one most in tension with the architecture.
2. **Default-run JSON contract**: after P1, does the compat-report move behind
   `--json`, `--compat-report`, or only emit on trap-limit to stderr? Affects any
   existing carrick tooling parsing the envelope.
3. **`--user` scope**: full uid/gid + supplementary-group switching (needs
   `--group-add`), or just `getuid()/getgid()` + file-ownership fidelity? Matters
   for the security claim.
4. **Daemonless restart semantics**: is `start`/`restart` = stop+recreate (re-fork
   a fresh supervisor; no live process to resume) acceptable vs docker's resume?
5. **Resource limits under HVF (P6)**: best-effort VM sizing / CPU accounting
   (xlarge, parity optics) vs permanently documented `--memory/--cpus` no-op-accept?
6. **`ps` auto-naming**: adopt docker's `adjective_surname` generator or a simpler
   scheme? Affects scripts keying on generated names.
7. **Noun-verb grammar**: also support modern `carrick container ps` /
   `carrick image ls` aliases (docker 25), or legacy top-level verbs only?

---

## Appendix A — Methodology

A background multi-agent workflow audited 7 dimensions in parallel
(run-flags, lifecycle commands, image management, output/stdio, networking/volumes,
isolation/resources, daemon-API/ecosystem). Each dimension's findings were then
**adversarially re-verified** against the source by a second independent agent
(every "missing" grep-confirmed, every "parsed-but-ignored" traced
args→`CliRunRequest`→`resolve_run_spec`→`RunSpec`→runtime). A synthesis pass
produced the roadmap; a completeness critic then caught duplicate/contradictory
ratings, four dependency inversions, orphaned findings, and missing test criteria
— all reconciled into this document.

**135 code-substantiated findings**: 1 true blocker (default-run), ~27 high, ~42
medium, ~62 low; 72 missing, 21 partial, 18 present, 16 divergent, 8
parsed-but-ignored. Key evidence anchors: `commands.rs:236,320-339,356`,
`engine/lib.rs:120,146`, `spec/lib.rs:99-125,185-208`, `dispatch/creds.rs:62-69`,
`image/lib.rs:269`, `lifecycle.rs:5,50,338-343`, `container.rs:286-292`,
`conformance.rs:291,326-327,370`.
