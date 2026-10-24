# Owner-triggered dispatch (#797, #799, #800)

Every trigger enters one agent loop on an owner's `[carrick-agent]` disposable
JIT clone. The controller caps the pool at four clones; the job cap is 60
minutes. Clones are destroyed after every job, including failure and timeout.
VM-local leases and template 9000 remain as in [Contabo setup](contabo-kvm.md).

## Admission and scope

The owner (`tjfontaine`, account type `User`) can start a run by:

- Applying `dispatch` or any `dispatch:*` label to an owner-authored issue.
  The suffix is free-text context for the model, never a model selector.
- Creating an unedited `/agent [free text]` comment on an owner-authored
  open issue or an owned dispatch PR, including a merge-conflicted PR.
- Submitting a `changes_requested` review on an owned dispatch PR.

The sender and triggering actor must both be the owner; the comment or review
author must also be the owner. A comment must have identical creation/update
timestamps, match `/agent` followed by whitespace or end-of-body, and still
match the original webhook when admission fetches it. Edited events and
non-owner triggers are refused. The guard never parses issue structure. The
loop reads the full issue, so #587's problem statement and acceptance need no
special heading. Unclear work can finish blocked with a question for the owner.

For issue work, the server starts `work/dispatch-<issue>-<run>`. The loop can
select another linked `work/dispatch-*` branch before invoking workers. A
candidate must have an open owned dispatch draft PR closing this issue, or an
authenticated earlier run's handoff recording its publication. The server
verifies the original run, workflow, owner identities and issue-scoped artifact
name, then reads the live remote tip. Without an open PR, the tip must equal
the latest authenticated handoff publication for that branch. A branch with
any closed or merged PR is refused. Reviews stay on the reviewed branch and
cannot call `select_branch`. A suggestive branch name alone grants no
authority. Other issues' branches, non-dispatch names and unlinked branches are
refused. The explicit `select_branch` tool is the sole request schema with a
branch field; no schema has issue, PR, repository or scope fields. PR triggers
start on their owned branch and require an open owner-authored linked issue.
The branch never comes from issue prose or coordinator notes. The checkout
preserves a conflicted branch and supplies the admitted main commit at
`refs/carrick/dispatch-main`. Rebasing and conflict resolution happen in the
isolated worker, before publication verifies main ancestry; runner-side Git
never stops the worker at a conflict.

The hosted guard compares review heads with the live PR before checkout or
build. Both hosted and clone admission check the live head again. For PR
comments, the hosted guard emits the observed head; clone admission and the
controller refuse a changed head. REST issue-comment runs lack the triggering
comment ID: successful steps in the trusted-main guard expose the webhook
issue/comment IDs and observed PR head in their names. The controller fetches
the comment and issue/PR independently, checking the owner, command, unedited
timestamps, ownership and head before provisioning or reassignment. No comment
body is used as a branch or executable selector.

The hosted guard resolves main for reviews and comments before checkout;
label events use their main event SHA. Both jobs check out the admitted base.
The clone fetches main and verifies the base is an ancestor before building
the driver. PR code is fetched and reconstructed as data, never compiled or
executed as the runner. The isolated worker may build its changes. Review YAML
still comes from GitHub's merge ref, so repository writers remain trusted for
that YAML, as in `ci.yml`. The controller refuses PR workflow modifications,
including renames and capped comparisons, as in #799. Comment YAML comes from
main. Issue/comment events serialize by webhook issue/PR number; reviews by
head ref. The expected-tip push lease closes cross-key races.

## Accounts and credentials

The runner holds the job-scoped `GITHUB_TOKEN` with exactly `contents: write`,
`pull-requests: write`, `issues: write` and `actions: read`. No long-lived write token or
publisher job exists. The tool server alone uses it for GitHub and publication.

The dedicated nologin accounts `carrick-dispatch-loop` and
`carrick-dispatch-agent` have distinct uids and groups, no sudo rights and no
runner group membership. The runner joins their groups and can sudo only to
those accounts, never root. Runner-owned 0700 state holds the driver, artifacts
and `redaction-secrets.json`. Model processes get `private_environment`, no
GitHub tokens, Actions command files or runner environment. The Unix tool socket
accepts only the loop uid through Linux `SO_PEERCRED`, refusing the worker uid.

`AGENT_DIRECTOR_TOKEN` is used only to bootstrap the pinned launcher from
private `carrick-sh/agy-director`. The workflow provisions every available
worker credential: `CODEX_AUTH_JSON` and `AGY_OAUTH_TOKEN`. Worker-private homes
contain only the selected backend’s credential subtree. The runner-private
capacity-query home retains both; the separate loop home holds only agy auth.
Codex can be absent; agy is required for the loop. These repository secrets are referenced only by
`dispatch-worker.yml`, enforced by workflow tests. The owner's Mac refreshes
them every 15 minutes; the director token is a read-only one-hour App token.
The App private key never leaves the Mac.

A model can read its own provider credential, including its refresh token,
and the pinned launcher. This is residual exposure, not a hardened secret
boundary. The private launcher is not secret (owner decision #231). Trusted
bodies can still misdirect a credential-bearing model. The collaborators-only
interaction limit expires on 2027-04-04 and is not a lasting trust boundary.
Earlier jobs capped exposure at 40 minutes; the current window reserves time
for bootstrap, a 45-minute loop and reporting. The job token can write branches belonging to other runs: the uid split and fixed refspec enforce normal scope, not its
repository grant. Ruleset 25522481 was deleted after it blocked merge queue
creation; tag ruleset 25523683 is active.

Both model uids retire through shared STOP/KILL, subreaper reaping and a
fail-closed real/effective uid census before cleanup and upload. A capacity
query also retires the worker uid. The accounts remain installed. Agent Git
configuration is discarded during reconstruction; runner Git never executes
agent hooks, filters or scripts. The clone is destroyed after the job.

## Policy tools and budgets

The loop runs Gemini Flash via `agy --model high`. It calls
`dispatch-worker tool <name>` with a JSON argument object on stdin. The
newline-delimited protocol rejects unknown fields in envelopes and arguments.
There are no tool arguments for issue, PR, repository or scope. Only `select_branch` accepts a branch, checked against issue linkage.

| Tool | Policy |
| --- | --- |
| `read_state {}` | Full issue and linked dispatch PRs (including closed state), reviews, inline comments, commits, issue/PR comments, earlier verified runs with URLs, conclusions, artifact names and outcome contracts. Includes their outcome comments and available branch candidates; board status is explicitly unavailable with this token. Includes the label/comment/review trigger verbatim and provenance. Two reads, bounded to 64 KiB; oldest items are dropped with a count, keeping the trigger. |
| `select_branch {branch}` | Before workers begin, selects the new run branch or an authenticated issue-linked branch. Reads and retains its remote tip for the publication lease. |
| `read_artifact {run, name}` | Reads one fixed text filename (`contract.json`, `handoff.json`, `raw.log`, `transcript.md`, `diffstat.txt`) from a completed earlier run. Verifies workflow/run/owner identity, a completed `carrick-agent` worker with successful upload, and the issue-derived upload bundle name. Review runs must keep the workflow blob from their head’s merge base with main. The returned contract, handoff or worker-transcript text is tagged with its dispatch provenance and marked untrusted. Rejects another issue, workflow, current run, expired/oversized bundle or unknown filename. Download is runner-private and the final read refuses symlinks and exceeds neither 64 KiB nor the event wall budget. |
| `read_capacity {}` | Runs pinned `agy_worker.py capacity --json` as the worker account. Reads the real `backends` map from `capacity_report`, with `installed`, `free_slots`, `quota_free`, `score` and agy `quota.groups`/`group_scores`. Augments it with exact current IDs from the launcher's live `models --backend` roster, excluding superseded IDs. Returns numeric capacity and model IDs only, never credentials or raw diagnostics. Only successful capacity reports are cached. Each admitted worker consumes its snapshot, so the next worker requires a fresh report; refused choices can reuse the current successful report. Total probes are capped at `workers + refused_workers`. Each subprocess/output is bounded (120 s, 64 KiB) inside the event wall budget. |
| `invoke_worker {notes, backend, model}` | Notes at most 8 KiB, with the model choice and reason. Checks remaining worker, tool-call and time budgets before consulting the cached capacity snapshot; refuses missing/uninstalled/full/exhausted backends and missing/exhausted models before charging either call or worker budget. Agy quota is checked for the selected model's group. Three refused worker requests exhaust their separate refusal budget without charging workers. Runs workers sequentially on the selected branch; each later worker sees earlier commits and a server-built handoff of contract summaries, tests and risks. All workers share 35 total minutes; owner trigger and inline review text are supplied verbatim, with coordinator notes separately labelled. |
| `publish {}` | Shared receipt/ownership checks; refuses `.github/workflows/*`; only the admitted branch, fixed refspec and expected-tip lease. Creates a draft with the first commit's title, PR template, `Closes #N` and run URL, or retains the owned PR. |
| `comment {body}` | At most 8 KiB; posts only on this issue or its continued PR, with token masking, credential redaction and a verified run footer. |
| `finish {status, summary}` | `done`, `blocked` or `failed`; posts an outcome with a bounded contract preview (full claims remain in artifacts), worker contract excerpt, selected backend/model and reasoning, budgets and run URL. One attempt, exempt from call budget; failed posting stops the loop and triggers one server fallback. |

The only ceilings are `[loop]` in `.github/dispatch-tiers.toml`: 12 tool calls,
two state reads, three workers, three refused worker requests, one publication,
two optional comments, 64 KiB state, 45 wall minutes including at most 35 total
worker minutes. There
are no dispatch tier tables or tier-selected credentials. The loop chooses
from live capacity and explains its choice in the outcome. No retries or
budget increases occur on refusals. If the loop exits or times out without
finishing, the server posts a failed fallback to the admitted issue/PR. Hard
cancellation or GitHub failure can prevent that network report.

Provenance is information, never authority. `owner` requires the owner User;
`dispatch-agent(run N)` requires a bot post with a verified last run footer,
repository, workflow, owner actors and a completed worker job on an agent
runner; comment and PR-body provenance survives artifact expiry or failed
uploads. Issue and comment runs use main; review runs require their workflow
blob to equal the head’s merge-base blob. Available issue/PR mappings must
match; artifact reads additionally require an issue-scoped uploaded bundle. Commit authors never grant owner or collaborator provenance: commits
are tagged `commit(author-claimed)`, and their messages are withheld unless
their SHAs belong to an authenticated handoff’s published-tip parent chain.
Deleted or invalid linked runs are skipped. History discovery retains all
known run IDs from linked branches and comment footers. An additional census
of at most 32 completed issue/comment runs of this workflow after issue
creation checks issue-derived artifact-name prefixes before authenticating
runs; it never scans the repository-wide artifact inventory. Each server
authenticates a run once and reuses its artifact listing and downloaded text.
Unchanged branch selections reuse history verification while rechecking live
remote tips and all-state PR ownership before admission or publication. Contracts from verified
artifacts take precedence over comment previews, and the server’s outcome
block precedes all model text. Write collaborators are tagged
`collaborator(login)`; all others are `unverified`, with bodies withheld. Lookups are cached. No provenance tag can
widen tool permissions. Admission is bound to the webhook digest in private
runner state; auth and the loop consume it without reinterpreting labels.

Output is token-masked and scanned before upload: `raw.log`, `transcript.md`,
`contract.json`, `handoff.json` and `diffstat.txt`, retained 30 days after successful or failed loop outcomes once uid retirement and artifact scanning succeed. The final contract and handoff persist each worker's claims and publication context for future runs; runs share no local state. Unknown or nonregular
files are refused. Worker contracts are claims for review; incomplete contracts
fail the job. PR review and repository gates establish correctness.

## Compiler isolation

Every worker-job step clears `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, both
`CARGO_BUILD_*` wrapper forms and sccache endpoints, and sets `CARRICK_SCCACHE=0`.
No restored toolchain objects or compiler server can build the credentialed
driver. Admission refuses a runner-owned sccache process or failed census.
Private Rust homes exclude Cargo config, credentials and symlinks to them.
Workers have no compiler-cache service or inherited endpoint environment.
Existing H1 executable witnesses exercise marker-writing wrappers and real
Cargo against dependency-free fixtures.

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
packages at run time. It sets `AGY_DIRECTOR_ROUTES=default` because the loop
names the backend explicitly.

The SDK's hash-locked wheels carry the complete codex package: `codex`,
`codex-code-mode-host`, `rg` and `bwrap`. The driver no longer fetches or
overrides a separate `codex` binary: `AGY_DIRECTOR_CODEX_SDK_BIN` is unset,
and `scripts/ci/inputs/agent-tools.json` has no codex tool. A lone `codex`
binary cannot run tools without `codex-code-mode-host`.

When the pinned launcher's `CODEX_SDK_VERSION` changes, regenerate the lock
file for the template's Python (3.13, x86_64) and rebuild template 9000.
The test `agent_template_prebuilds_the_hash_locked_codex_sdk_the_driver_uses`
ties the builder, the lock file and the driver together.

## Rollout and live acceptance

Portable tests cover trigger trust, capacity refusal without charges, branch
ownership, publication, socket/environment isolation and workflow wiring. They
cannot establish deployed acceptance. The director must push from the Mac
(App tokens cannot push workflow edits), deploy the new controller and verify
agent-template accounts/tools and the pinned launcher roster/capacity APIs.
Then label #587 as written with `dispatch`, observe a draft PR, request changes
as owner, and observe a new commit on that PR branch plus an outcome comment.
Exercise `/agent` on an issue and a merge-conflicted owned PR, verify refusal
of edited/non-owner comments and an unowned PR, and confirm both model uids
retired. These trials also complete #799's pending live acceptance.
