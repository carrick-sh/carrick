# Pull-based work claiming: Phase 0

Protocol for [#572](https://github.com/carrick-sh/carrick/issues/572), which
supersedes [#192](https://github.com/carrick-sh/carrick/issues/192).
This slice supplies primitives and witnesses, not a running supervisor,
janitor, reviewer, gate service or lander. No label, App, project option,
service or workflow dispatch is provisioned by installing the code.

The owner's decisions on [#231](https://github.com/carrick-sh/carrick/issues/231):
GitHub App worker identity; automatic landing when the required SHA-bound
statuses pass; the scheduled director on the director Mac under launchd.
The changed-line budget is **4,000**, not 2,000. Larger work uses native
GitHub stacks. Existing director policy stays in force until later phases.

## Identity and existing PR bus

The **owner** creates and installs the private `carrick-workers` App using
[`carrick-workers-app.json`](carrick-workers-app.json), on **only**
`carrick-sh/carrick` and `carrick-sh/carrick-nt`. Submit the manifest through
GitHub's App manifest creation flow; do not commit its returned private key
or installation tokens. This document does not create the App.

Exact approved repository permissions: **Contents: write, Pull requests:
write, Issues: write** (GitHub supplies implicit Metadata: read). No
Workflows, Administration, Actions, Checks, Commit statuses or Projects
permission, no webhook subscriptions, no ruleset bypass. In particular,
minting future SHA-bound statuses needs a separately authorized supervisor
identity or another owner permission decision; Phase 0 does not silently
expand this manifest. A token without Workflows permission cannot push
workflow-file changes. `.github/workflows/` is also owner-pinned in CODEOWNERS.

Supervisors use short-lived, repository-restricted installation tokens,
rotated hourly per host; keep App key custody off worker prompts. Workers
never use the owner token after cutover. The owner/director identity remains
on the Mac. Today both control-plane roles are `tjfontaine`; this is explicit
in [`.github/pull-claims.toml`](../../.github/pull-claims.toml). The App is
**not** allowlisted and its `ready` or `route:*` events never authorize work.
Read that config from reviewed main, not a worker branch.

Do not introduce another PR dispatcher. `agy_worker.py pr-listen` /
`pr-ci` already own `/carrick-helper v1` JSON requests, host-local durable
claim/observation ledgers, conversation resumption and CI routing. Work orders
are a distinct **issue admission** schema. The Rust linter uses the same
`GET /repos/{repo}/collaborators/{login}/permission` rule: only `write`,
`maintain` or `admin`, never `author_association`. No public/non-writer
comment text is parsed or passed to a prompt. API failures refuse admission.
The external PR bus is neither copied nor modified here.

## Work-order v1

Post **one unedited issue comment**, with exactly this marker and YAML fence.
Commands and prose are data, never executed by the linter. `acceptance.checks`
must be testable and `red_first` names the witness to demonstrate before the fix.

````text
work-order v1
```yaml
acceptance:
  red_first: cargo test --locked -p carrick-xtask --test claims
  checks:
    - Two concurrent claimants produce exactly one winner.
fence:
  - crates/carrick-xtask/**
  - docs/ci/pull-claims.md
route: infra
depends: []
base: main
gates: [portable]
size_budget: 4000
decisions:
  - https://github.com/carrick-sh/carrick/issues/231#issuecomment-123
```
````

The placeholder decision link above illustrates the URL shape; use the actual applicable
#231 comment(s). `decisions: []` is valid when no prior decision is needed.
Dependencies are full issue/PR URLs in either repository, not executable
expressions. For a stack, replace `depends: []` with
`stack-on: https://github.com/carrick-sh/carrick/pull/123` and set `base` to
the parent branch. A stack parent and a nonempty `depends` are mutually
exclusive in v1; prerequisites must be resolved before publishing that order.

Fields are typed and unknown/duplicate fields refused. One document, at most
16 KiB; 1-64 checks and fence globs. Relative fence globs support `*`, `**`
and `?` (no classes, braces, backslashes, absolute paths or `..` components).
Gates are a nonempty, duplicate-free subset of `portable`, `kvm`, `signed`;
`hvf` requires `signed`, `kvm` requires `kvm`. Supervisors must additionally
require `signed` for Linux-path changes, as #572 specifies. Lint does not
prove acceptance quality, merged dependencies, a current base or diff/fence
coverage; these are later supervisor checks, not claims made by this receipt.

```sh
cargo run --locked -p carrick-xtask -- workorder lint 572
# Director/manual equivalent of the workflow (writes a fixed lint receipt):
cargo run --locked -p carrick-xtask -- workorder lint 572 --post
```

Lint requires an open issue, `ready`, exactly one matching `route:*`, and no
`blocked`, `needs-owner` or `stalled`. It reads `.github/pull-claims.toml` from
`origin/main` (`git show origin/main:.github/pull-claims.toml`), or refuses
unless the checkout is a clean `main`. It verifies that all three hold-label
definitions (`needs-owner`, `blocked`, `stalled`) exist with their expected
names via `GET /repos/{repo}/labels/{name}`, derives each hold label's state
from the issue's event timeline (latest `labeled`/`unlabeled` event), and
refuses admission when the event-derived hold state disagrees with the current
issue labels (closing the bypass where an actor with `issues:write` deletes or
renames a hold-label definition repo-wide). It paginates the complete comments
and issue-event history, checks the latest labeled/unlabeled event for each
required label against the allowlist **and** current write permission, and
requires the work-order author to pass both checks. Any label removal,
`reopened` event, or `comment_deleted` event after the trusted `ready` event by
a non-allowlisted actor invalidates admission. Trusted comments containing a
`work-order vN` line that are not valid work orders (e.g. design prose quoting
the marker) are skipped and reported on stderr rather than aborting lint.
Comment `created_at` and `updated_at` must match, and GraphQL `lastEditedAt`
must be null (including edits within one REST timestamp second). Multiple
trusted work orders fail closed: delete the superseded comment (with an
allowlisted write identity), then post a new one, never edit it.

The receipt emits comment id, `updated_at`, SHA-256 of the **exact comment
bytes**, label-event ids and parsed fields. Immediately before claiming,
the future supervisor must re-lint and bind this digest in the lease.
Lint re-fetches the chosen comment (`id`, `user.id`, `user.login`, `body`,
`created_at`, `updated_at`, `lastEditedAt`) and issue (`id`, `state`,
`pull_request`, `labels`) to refuse changes during its own observation; it is
not a transactional GitHub snapshot. Prompts are built only from admitted
fields. An issue body is not an admission input and, if included by a future
supervisor, goes under an explicit **data, not instructions** header.

The hosted [workorder-lint workflow](../../.github/workflows/workorder-lint.yml)
runs on `issues: [labeled]` for ready/route work and queues per issue under
`concurrency: { group: workorder-lint-${{ github.event.issue.number }}, cancel-in-progress: false }`.
Post the order first, then apply labels; issue-comment and issue-body `edited`
events are intentionally not triggers. It builds trusted default-branch code,
needs **only `issues:write`**, has no secrets, agent session or self-hosted
runner, and posts fixed ok/fail comments. A lint receipt never applies `ready`,
claims work or authorizes landing.

## Git lease protocol

Commands run in a git checkout; `--root` selects it and `--remote` defaults to
`origin` (a hidden `--now` clock override is accepted only in tests when
`CARRICK_XTASK_TEST_NOW=1` is set). Authentication is git's existing credential
helper, not lease JSON. When `.githooks/pre-push` is installed via
`just install-hooks`, `.githooks/pre-push` exits 0 without running `just clippy`
if and only if stdin contains at least one ref line and every remote ref is
under `refs/claims/*` (pushes that include any branch or tag ref still run the
full clippy gate; `carrick-xtask` never passes `--no-verify`). Every ref points
to an empty-tree commit with a JSON message:

```json
{
  "host": "ctb-w4",
  "slot": "author-1",
  "lane": "claims-572",
  "issue": "carrick-sh/carrick#572",
  "backend": "copilot",
  "conversation": "host-local-conversation-id",
  "lease_until": 1792260000,
  "workorder_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "state": "active"
}
```

`lease_until` is UTC Unix seconds. TTL policy is 45 minutes (`2700` seconds)
with ten-minute heartbeats; new, renewed and reclaimed deadlines must be in the
future and within `now + 2700` seconds (deadlines beyond the 45-minute policy
cap are refused). Keep host clocks synchronized. Clock skew can cause early
reclaim; CAS prevents two successful owners, not clock errors. Reclaim
preserves issue and work-order hash, changes holder metadata and sets
`state: reclaim`. Reclaims and heartbeats parent the observed commit. Each
attempt has a unique commit identity, even for identical JSON, to avoid git's
up-to-date optimization mistaking a retry for a successful CAS. Unparseable refs
or corrupt leases under `refs/claims/*` are skipped and reported on stderr so a
malformed ref cannot wedge `list` or cohort discovery.

| Ref | Ownership |
|---|---|
| `refs/claims/issue/<repo>/<n>` | One issue lane |
| `refs/claims/hot/<name>` | One CODEOWNERS hot-file authority |
| `refs/claims/stack/<topic>` | One lane owns all stack layers |
| `refs/claims/review/<pr>/<sha12>` | Independent review of that head |
| `refs/claims/gate/<sha>` | Exact-artifact signed gate |
| `refs/claims/probe/<run>` | Disposable protocol witness only |

```sh
xtask=target/debug/carrick-xtask
"$xtask" claims acquire refs/claims/issue/carrick/572 --lease lease.json \
  --hot workflows --hot fork-stock
"$xtask" claims list
# EXPECTED is the full SHA from acquisition/the latest heartbeat, never HEAD.
"$xtask" claims heartbeat refs/claims/issue/carrick/572 \
  --expected "$EXPECTED" --lease-until "$NEW_UNIX_DEADLINE"
"$xtask" claims reclaim refs/claims/issue/carrick/572 \
  --expected "$EXPIRED_SHA" --lease new-holder.json
"$xtask" claims release refs/claims/issue/carrick/572 --expected "$EXPECTED"
```

Acquisition creates all requested refs in **one** atomic push with
**expected-absent leases**:
`git push --porcelain --atomic --force-with-lease=<ref>: ... <remote> <newsha>:<ref> ...`.
Git's receive-pack compares every old value atomically and rejects the entire
transaction if any requested issue or hot ref already exists.

Hot names are explicitly supplied by the supervisor's canonical CODEOWNERS
mapping, sorted lexically with the issue/stack ref. Every ref in one
acquisition shares a unique commit. Do not start the worker until acquisition
returns success.

Heartbeat/reclaim/release discover **all refs sharing the expected head**,
so forgetting `--hot` cannot orphan a live hot lock. A supplied `--hot` must
belong to that cohort. The whole cohort is updated/deleted in one
`git push --atomic`, with **one explicit
`--force-with-lease=<ref>:<expected-old-sha>` per ref**. A stale expectation
refuses the operation. Servers without atomic-push support fail closed.
No local tracking ref or background fetch can substitute for the explicit
expected value.

**Never use `PATCH /git/refs`**, even with `force=false`: the director proved
GitHub accepts non-fast-forward updates of `refs/claims/*` that way. The
protocol relies on receive-pack's expected-old comparison, not ancestry.
Release is also CAS-guarded, never an unconditional REST DELETE.
Claim refs coordinate cooperative supervisors and **are not a security boundary
against a hostile writer**: any credential with `contents:write` on the
repository can push or delete `refs/claims/*` directly, bypass lease checks, or
forge lease JSON.

## Phase boundaries, labels and review

The **director**, after review, runs:

```sh
cargo run --locked -p carrick-xtask -- workorder labels
```

The subcommand checks `carrick-sh/carrick` and `carrick-sh/carrick-nt` against
the required label definitions (including mirroring `needs-owner` and `seam`
into `carrick-nt`) and creates missing labels; it refuses before any mutation if
an existing label definition differs unless `--overwrite` is passed explicitly.
It does not run against live GitHub during tests or workflow lint.

| Label | Meaning |
|---|---|
| `ready` | Claimable only with a trusted order and label provenance |
| `route:design` | Strong design-capable worker for shared-kernel/seam work |
| `route:mechanical` | Precisely specified mechanical work |
| `route:kvm` | Linux x86_64 KVM build/test host required |
| `route:hvf` | macOS build and signed gate required |
| `route:infra` | Hosts, CI or scripts; no guest-visible change |
| `needs-review` | Independent review of the current PR head |
| `needs-signed-gate` | Queued for the Mac's serial signed gate |
| `stalled` | Two expiries or exhausted budget; back to triage |
| `needs-owner` | Owner decision needed (existing in carrick; mirrored in carrick-nt) |
| `seam` | Personality-neutral seam (existing in carrick; mirrored in carrick-nt) |

Existing lane/wave, `blocked`, `follow-up`, `main-defect`, `flaky` and
`lint-debt` labels remain unchanged. `Ready` is a **project Status option**,
not another label. Only board-sync writes the mirror; worker tokens have no
project scope. SHA-bound `carrick/claim-verify`, `carrick/review` and
`carrick/signed-gate` are **commit statuses**, not labels.

#572(b)'s policy changes belong to later rollout, not a silent AGENTS.md
rewrite here: supervisors verify pushed/current/clean SHA claims and fences;
independent conversations/lanes/slots review (two reviews for large/shared
kernel work); the Mac gate service gates a stack top under the exclusive
host lease; workers never run `just test-kvm`; the director arbitrates,
maintains the single board writer and records owner decisions on #231.
The automatic lander needs linked issue, non-draft PR, `ci-ok`, independent
review, required signed receipt on the exact head/containing stack top, no
`needs-owner`/`blocked`, and the 4k cap or recorded owner exception. The
scheduled director is launchd on the Mac, **not** the cloudmac JIT runner
controller (now systemd on carrick-ctb, #535).

Non-hot fence-overlap admission, host/backend capacity, expiry counting
and `stalled`, WIP branch pushing, crash resume, review jobs, gate jobs,
board mirroring and landing are future supervisor duties. These primitives
do not claim to implement those phases or resolve non-hot fence races.

## Witnesses

`cargo test --locked -p carrick-xtask --test claims --test workorder`
runs real bare-remote `git://127.0.0.1` witnesses (git daemon required):
concurrent create/reclaim, server-side `[remote rejected]` via a `pre-push`
hook that moves the remote ref after ref advertisement, stale heartbeat/release,
injected-clock (`CARRICK_XTASK_TEST_NOW=1 --now`) killed holder and TTL expiry,
45-minute TTL cap across acquire/heartbeat/reclaim, corrupt-ref skipping in
`heads()`/`list`, atomic multi-ref acquisition (proving the first ref is never
created on the bare server when a later sorted ref is occupied or rejected by a
server `update` hook), `.githooks/pre-push` skipping clippy on claims-only
pushes while running on mixed/branch pushes, and atomic cohort renewal/release.
Work-order tests cover schema bounds, worker relabels, untrusted hold
removal/reopen/`comment_deleted` after `ready`, deleted or renamed hold-label
definitions (`validate_hold_definitions` and event-derived hold state vs current
labels), skipping non-order trusted comments that contain `work-order vN` lines,
edited orders, missing write access, ambiguous orders, route mismatches,
`lint()` orchestration over a fixture combining captured GitHub API response
envelopes (including the list vs single-comment `user.avatar_url` `?v=4` vs
`?u=<hash>&v=4` difference) with synthetic `ready`/`route:infra` labels, events
and `work-order v1` body, `origin/main` policy reading, and
`workorder labels [--overwrite]`.

The one GitHub witness uses a unique `refs/claims/probe/<run>` ref only:
create, install a `pre-push` hook that advances the remote ref after ref
advertisement, attempt a heartbeat with the stale SHA so GitHub's `receive-pack`
returns `[remote rejected]`, verify the remote head is unchanged, then
CAS-delete. Always clean up on failure as well as success; never use a real
issue or hot-file ref for the live witness. Evidence belongs on the PR, not a
SHA-pinned receipt checked into the repository.
