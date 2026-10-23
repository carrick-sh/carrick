# Issue-label dispatch (#634, #733)

Only the owner, account type `User`, may label or rerun an owner-authored issue.
The hosted guard, driver and clone controller enforce admission and the
checked-in `dispatch:<tier>` allowlist. The worker runs on `[carrick-agent]` in a
one-job disposable JIT clone. The controller caps the pool at four clones;
the worker job has a 60-minute cap (label worker turns keep their earlier limits). Clones are destroyed after every job,
including failure and timeout. VM-local leases and protected template 9000
remain as documented in [Contabo setup](contabo-kvm.md).

## Credentials and execution

The job-scoped `GITHUB_TOKEN` has exactly `contents: write`,
`pull-requests: write` and `issues: write`; it cannot create check runs.
Workflow steps use it for continuation admission, pushing the assigned branch,
and reporting results. There is no long-lived write token or publisher job.
Draft-PR review and repository gates establish content correctness.

The hardened agent template pre-creates the dedicated system account
`carrick-dispatch-agent`: no login shell, sudo rights or runner group membership.
It enters the agent tree with `sudo -n -u carrick-dispatch-agent -- /usr/bin/env
-i`. Runner-owned 0700 directories hold the driver, upload population and
`redaction-secrets.json` outside the agent tree. The agent cannot read runner
process environments or alter those files. The driver copies only selected
provider auth, tools and private Rust homes into a separate tree, hands it to
the account through group-readable staging, and supplies an explicit
environment without GitHub tokens or Actions command-file channels.

`AGENT_DIRECTOR_TOKEN` is a bootstrap-only read credential for the pinned private
`carrick-sh/agy-director` launcher. Label events receive only the selected tier's `CODEX_AUTH_JSON` or
`AGY_OAUTH_TOKEN`. Review events also receive agy auth for the loop; each
account gets only its own provider files. The selected provider credential is intentionally
readable by the agent and may include a refresh token. This is a residual
credential exposure, not a claim that the agent cannot extract that credential.
The agent can also read the pinned launcher it runs from and could publish it
in its own draft PR; the launcher is private to keep Python out of the carrick
tree, not because it is secret (owner-accepted residual, #231).

After exit or timeout, the driver stops and kills processes by both real and
effective agent UID, including detached sessions. A subreaper reaps adopted
children; a fail-closed census must find none before hand-back, scanning,
completion or upload. Retirement runs STOP/KILL against all processes as the
agent uid, repeats a bounded census and refuses completion if any survive.
The account remains installed; the driver never creates or deletes users.
Agent-controlled Git config is discarded when files and objects are copied into
a fresh runner repository; checkpointing never runs that config as the runner.
The whole clone is destroyed after the job.

Earlier jobs capped this exposure at 40 minutes; the current 60-minute job
window reserves time for bootstrap, a 45-minute loop and reporting. The job token can write issues/PRs and any
`work/dispatch-*` branch, including branches belonging to other runs. Driver
branch selection narrows normal publication, not the token's repository grant.
Branch-scope ruleset 25522481 was deleted (it blocked merge-queue branch
creation; owner decision, #231). The loop server holds the token while isolated model processes run; branch
scope rests on the uid boundary and the driver’s fixed refspec. Tag ruleset 25523683 is active. The issue
must be owner-authored, but collaborators may have edited its brief before
labeling; the owner must review it. Provider credential trust and review of
agent changes remain necessary.

### Secret provisioning

The workflow has no GitHub environment; `AGENT_DIRECTOR_TOKEN`,
`CODEX_AUTH_JSON` and `AGY_OAUTH_TOKEN` are repository secrets, and only
`.github/workflows/dispatch-worker.yml` may reference them (enforced by
`only_dispatch_workflow_references_dispatch_secrets` in
`crates/carrick-xtask/tests/dispatch_workflow.rs`). They are refreshed every 15
minutes from the owner's Mac by a launchd job: the Codex and agy logins are
copied as-is, and `AGENT_DIRECTOR_TOKEN` is a freshly minted one-hour
`carrick-workers` App installation token, read-only on
`carrick-sh/agy-director`. The App private key never leaves the Mac. No write
token is minted; all writes use the job's own `GITHUB_TOKEN`. Any new workflow
that references these names widens their exposure and needs owner review.

## H1 compiler isolation

The whole worker job overrides `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` and
both `CARGO_BUILD_*` wrapper forms to empty, sets `CARRICK_SCCACHE=0`, disables
sccache and clears its endpoint selection. No rust-cache action runs. No
restore-only toolchain cache is used. The first
worker step refuses admission if the runner UID owns an sccache process or the
process census fails; it never contacts that service. Templates must not
prestart one.

Rust homes are physical private copies. Both Cargo home configuration files
(`config` and `config.toml`), including symlinks and their `[env]` entries, and
Cargo registry `credentials`/`credentials.toml` are excluded. The agent command sets both Rust wrappers explicitly empty and
`CARRICK_SCCACHE=0` and inherits no `SCCACHE_*` variables. The unchanged H1
witness plants a marker-writing wrapper in each Cargo config filename, runs
real Cargo against a dependency-free fixture, and checks successful compilation,
absence of the marker, and absence of runner endpoint variables. The workflow
witness exercises runner-UID admission for present, absent and failed censuses.

## Branches, reporting and artifacts

A fresh job uses only `work/dispatch-<issue>-<run_id>`, derived from the admitted
issue and Actions run ID. Completion refuses a different current branch and
pushes only `HEAD:refs/heads/<assigned branch>`, with an explicit tip lease,
without tags or submodules. A fresh branch must be absent remotely. A rerun reports an existing owned
branch/PR without replacing it; an identical already-pushed tip can finish
creating a missing PR. Workflow-file changes under `.github/workflows/*` are
refused with an issue/summary report and artifacts instead of attempting a
push the job token cannot authorize.
The workflow creates a draft PR as `github-actions[bot]`, using the repository
PR template, `Closes #N` and its workflow-run URL.

For a later `/agent continue`, the owner brief's `Branch:` directive may name
that original run-derived branch. Directives inside comments or fences are
ignored. Continuation requires an open draft PR authored by `github-actions[bot]`
in this repository, matching the issue and branch, with the original run URL.
The referenced run must belong to this dispatch workflow on main, triggered by
an owner issue event. There is no App-authored ownership marker. The driver
records the fetched tip before agent execution and the push lease refuses a
concurrent change. Existing PR bodies remain intact; completion posts a comment.

The workflow masks the job token before execution. Completion masks token bytes
in every upload, scans the fixed upload population and refuses unknown or
nonregular files. Uploads contain `raw.log` (stdout and stderr),
`transcript.md` (rendered agent log and contract summary), `contract.json` and
`diffstat.txt`, retained for 30 days. JSON masking preserves the contract shape.
Command diagnostics retain their independent credential masking.
The workflow posts the run summary and issue/PR comments after the agent exits;
API reports are bounded and link to the full artifacts. Incomplete contracts
still produce artifacts and make the final job verdict fail.

Runner-only Linux tests (`--include-ignored --test-threads=1`) exercise real
OS permissions, detached-process retirement and completion with a fixture
launcher and local Git/GitHub stand-ins. They run on the hardened template
from `scripts/ci/build-template-debian.sh INPUT_DIR SCRIPT_COMMIT XTASK agent`.
They skip only when the pre-created account is absent; report those witnesses
as unrun. The director must rebuild the old worker template before rollout.
Runner sudo grants target only `carrick-dispatch-agent` and
`carrick-dispatch-loop`; runner cannot become root and neither model account
has sudo rights. Portable tests
cover workflow selection, permissions, auth custody, H1 and branch policy. They do not establish
live deployed acceptance. The post-landing default-branch trigger and fresh-clone
trials remain with the director under #634.

Runner belongs to the agent's private group; the agent never belongs to the
runner group. After verified retirement, the driver reads agent files only
as data. It never executes or sources agent-written scripts, Git hooks or
configuration. Git runs against a reconstructed snapshot with hooks and
configuration disabled, never by changing into the agent tree to run commands.

## Agent template pool and ACLs (#762)

Template 9000 is a clone source **outside** the `carrick-ci` pool. Template
300 stays in the pool, and clones from either source are created in the pool.
Pool membership grants administrative VM rights and must never be used for
9000. Changing `carrick-ci` pool membership is a controller-affecting shared
change: announce it before and after under AGENTS.md's “Multiple director
sessions” rules.

The owner applies the source ACL to both the user and its privilege-separated
token; both grants are needed:

```sh
pveum acl modify /vms/9000 --roles PVETemplateUser --users ci-scaler@pve
pveum acl modify /vms/9000 --roles PVETemplateUser --tokens 'ci-scaler@pve!elastic'
```

With agent clones enabled, startup requires exactly `VM.Audit=1` and
`VM.Clone=1` on 9000. The controller reads its configuration directly because
its pool inventory intentionally excludes this source. The root-run builder
uses `qm` to start and stop the agent template during provisioning; the
controller token retains only its inspection and clone rights.

### Codex SDK

The agent template builds `/opt/carrick-agent/codex-sdk` once from
`scripts/ci/inputs/codex-sdk-requirements.txt`. It installs hash-locked wheels
with `--require-hashes`. The SDK is root-owned and read-only to the agent.

The driver sets `AGY_DIRECTOR_CODEX_VENV` to that path, so no job installs
packages at run time. It sets `AGY_DIRECTOR_ROUTES=default` because the tier
table names the backend explicitly.

The SDK's hash-locked wheels carry the complete codex package: `codex`,
`codex-code-mode-host`, `rg` and `bwrap`. The driver no longer fetches or
overrides a separate `codex` binary: `AGY_DIRECTOR_CODEX_SDK_BIN` is unset,
and `scripts/ci/inputs/agent-tools.json` has no codex tool. A lone `codex`
binary cannot run tools without `codex-code-mode-host`.

When the pinned launcher's `CODEX_SDK_VERSION` changes, regenerate the lock
file for the template's Python (3.13, x86_64) and rebuild template 9000.
The test `agent_template_prebuilds_the_hash_locked_codex_sdk_the_driver_uses`
ties the builder, the lock file and the driver together.

## Review continuation (agent loop)

An owner `changes_requested` review on an owned dispatch draft PR starts a
continuation on its existing `work/dispatch-<issue>-<run>` branch. The review
author, sender and triggering actor must all be `tjfontaine` (`User` for the
webhook identities). Admission verifies the bot-authored draft, same-repo head,
`Closes #N`, original dispatch run and its owner/workflow/main identity. It
fetches the linked issue again: it must be open, owner-authored and have exactly
one allowlisted `dispatch:*` label. That label fixes the worker tier. The event
fixes the repository, issue, PR and branch. A `Branch:` issue edit and relabel
are unnecessary; the label path retains its fixed script until #800.

The hosted guard resolves main before checkout and emits its admitted SHA as
`base`. Both jobs check out that SHA for reviews. Before compiling the driver,
the clone fetches main again and verifies `base` is its ancestor. Driver
production and publication use that admitted base, never the review event's
`GITHUB_SHA` merge commit. PR objects are fetched and reconstructed as data;
credentialed runner code never builds or executes the PR's driver. The worker
may build and test its changes only under its isolated account. Workflow YAML
itself still comes from GitHub's merge ref: repository writers remain trusted
for that YAML, as in `ci.yml`. Publication refuses `.github/workflows/*`.

The controller admits only owner review runs from this repository and workflow
on dispatch head refs. Review-run REST metadata uses the PR head SHA, while
`GITHUB_SHA` names the merge commit. The job hook reads the head identity from
the runner-written webhook and retains the exact run/attempt/head-SHA binding;
it separately validates the merge ref and workflow ref. This identity is never
the driver build base. The pinned runner writes the webhook before invoking
its hook ([runner v2.337.0 source](https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/JobHookProvider.cs)).
The server repeats the full review and PR checks. Issue events serialize on the
issue number, review events on the PR head ref. These are different concurrency
keys, so a label run and a review run can overlap. The shared publication code's
`--force-with-lease` against the fetched tip refuses a racing update.

`dispatch-worker loop` runs as the runner and holds the job token. It launches
Gemini Flash with `agy_worker.py --foreground --backend agy --model high` as the
new nologin account `carrick-dispatch-loop`. That account has its own private
home with only agy auth, no worker Codex credential, GitHub token, runner
environment or Actions command files. The runner joins each model account's
separate group and can sudo only to those accounts. Workers still use
`carrick-dispatch-agent`. Both uids must retire with the shared STOP/KILL helper
and verified real/effective uid census before cleanup and upload.

The model uses the copied driver client, `dispatch-worker tool <name>`, with a
JSON argument object on stdin. The runner's Unix socket checks Linux
`SO_PEERCRED` against exactly the loop uid, refusing the worker uid. Requests
are newline-delimited JSON with unknown fields rejected at both envelope and
argument levels. No argument schema has repository, issue, PR, branch or tier
fields. Reading an injected instruction therefore cannot authorize another
destination or a tier change.

| Tool | Arguments and server policy |
| --- | --- |
| `read_state` | `{}`; at most twice per event. Returns this issue and PR plus reviews, inline comments, issue and PR comments, with provenance. Unverified items contain only author identity, timestamps and `body withheld: unverified`. Drops oldest items by creation/submission time to fit 64 KiB, keeping the triggering review, and reports the drop count. Refuses if the triggering review alone exceeds the response budget. |
| `invoke_worker` | `notes` up to 8 KiB; invokes the shared isolated worker path once on the admitted PR branch with the issue's tier. The server supplies the review body and owner inline comments verbatim. Loop notes appear under `Coordinator notes (not owner instructions)`. |
| `publish` | `{}`; shared receipt/ownership/workflow checks and publication, only to the admitted branch with its expected-tip lease, once. |
| `comment` | `body` up to 8 KiB; posts only on this PR, with exact token masking, credential redaction and a `Dispatch run:` footer, at most twice. |
| `finish` | `status` (`done`, `blocked`, `failed`) and `summary` up to 8 KiB; posts the mandatory outcome with worker contract excerpt, budgets used and run URL, then ends the event. Exempt from the call cap and succeeds only once. |

The `[loop]` table in `.github/dispatch-tiers.toml` owns the limits: 12 total tool
calls other than `finish`, two state reads, one worker, one publication, two
optional comments, 64 KiB state, 45 minutes including the worker, and a worker turn at most 35 minutes. The job
has a 60-minute ceiling. Budget exhaustion returns a refusal without crashing
the server. If the model exits, times out or fails without `finish`, the server
posts a failed fallback outcome on the same PR. A hard job cancellation or lost
GitHub connectivity can still prevent that network report.

Provenance supplies information, never authority: `owner` requires the owner's
`User` identity; `dispatch-agent(run N)` requires a bot post with a run URL
verified against this repository, dispatch workflow and owner actor. Issue
runs must have `head_branch == main`; review runs must have this issue's
dispatch head ref; issue runs must map to this issue where their branch or PR
metadata permits that check. The last `Dispatch run:` footer supplies the run id.
Other users with verified write access are `collaborator(login)`; everything
else is `unverified`. Only owner, verified dispatch-agent and write collaborator
items retain their bodies and inline text. Permission lookups per login and run
lookups per id are cached for the event. No provenance tag widens tool permissions.

The loop model's shell can read its own agy credential in its home. Withholding
unverified text reduces public-comment injection, but trusted bodies can still
misdirect a credential-bearing model. The public repository's collaborators-only
interaction limit expires on 2027-04-04; it is not a lasting trust boundary.

The clone's credentialed `guard --admit` stores the validated Dispatch (including
tier, backend and base) and triggering review in private runner state, bound to
the webhook digest. Auth and the loop consume that snapshot without resolving
issue labels again; auth makes no API requests and needs no GitHub token. The
controller checks the shared owner/run identity and bot-owned draft PR predicate
before admitting review demand and again before provisioning or reassignment.
It rejects an available review state other than `changes_requested`, and requires
the workflow blob at the run head SHA to equal the current main workflow blob.
The hosted guard job skips unrelated review events before allocating work.

A merge-conflicted PR has no merge ref, so GitHub does not fire this review
event. An owner `/agent` comment trigger is deferred to #800. The director must
push workflow changes from the Mac, rebuild the agent template (new account,
group and sudoers drop-in), and deploy the controller's review admission. The
live acceptance remains director-run: request changes on a throwaway dispatch
PR after landing, observe a new commit on that PR branch and an outcome comment
without issue edits or labels, and confirm both model uids have retired.
