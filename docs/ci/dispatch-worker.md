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
`pull-requests: write`, `issues: write` and `actions: read`. The tool server
alone uses it for GitHub reads, comments, closing-reference checks and run
lookups. Publication also uses it when the publish credential is unavailable.

`DISPATCH_BOARD_TOKEN` is a separate one-hour `carrick-workers` App installation
token, down-scoped at mint to `{"organization_projects":"write"}`. Only the
loop step receives the secret, and only the runner-uid tool server uses it.
Both model accounts receive cleared environments. The workflow masks it before
the loop starts; diagnostic redaction and the complete artifact scan also cover
its exact bytes. No App private key enters GitHub Actions. The director adds
the Mac minter after landing; until the secret exists, reads and status updates
report `unavailable` with the missing-token reason and the run continues.

`DISPATCH_PUBLISH_TOKEN` is a separate one-hour `carrick-workers` App
installation token, down-scoped at mint to
`{"repositories":["carrick"],"permissions":{"contents":"write","pull_requests":"write"}}`.
Only the loop step receives it. The runner-uid tool server uses it only for the
fixed-refspec branch push and PR creation or body PATCH, including restoration.
Git and GitHub subprocesses receive it as `GH_TOKEN` only for those writes;
reads, comments, closing-reference checks and run lookups keep the job token.
The director adds the Mac minter after landing; no App private key enters the job.
Both model accounts receive cleared environments, and the publish token is
masked and included in diagnostic redaction and the complete artifact scan.
The App has no workflow permission, so dispatch continues to refuse workflow
file changes and reports an App push refusal explicitly.

The publish token shares the `carrick-workers` App identity with the ctb-w1..w4
worker VMs, which run untrusted LLM workers. Comments, reviews and inline
comments deliberately authenticate dispatch output only from
`github-actions[bot]`; the publish token never posts them. A separate App for
dispatch publication is a pending owner decision.

App-created PRs are authored by `carrick-workers[bot]`. Besides the existing
run, branch, draft and issue checks, ownership requires that the exact PR
number appears as `publication_pr` in an authenticated creation-run handoff
or an Actions-authored server outcome receipt. The branch must be that run's
`work/dispatch-<issue>-<run>`. An App PR without that binding stays unverified
and its body is withheld. The private server records the number returned by a
successful create before verifying its newly created PR, then publishes that
binding in its handoff and outcome. The controller, hosted guard and loop use
the same evidence resolver. If an earlier run pushed a branch but never
created its PR, a later run creates that PR with the job token: it cannot add
an App publication binding to the original run's immutable artifacts.

If the publish secret is absent or empty, publication uses the job token. An
authentication failure from an App push, PR create or body PATCH retries
that operation once with the job token and keeps the job token for the rest
of publication,
including restoration. Bad credentials, HTTP 401 and Git's authentication or
missing-username errors qualify. Lease rejections, network failures and 403
workflow or permission refusals do not retry. The outcome says CI won't start
automatically and asks a person to mark the PR ready only after a push or PR
write actually happened. Falling back does not fail the run.

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
for bootstrap, a 42-minute loop and reporting. The job token can write branches belonging to other runs: the uid split and fixed refspec enforce normal scope, not its
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
| `read_state {}` | Full issue and linked dispatch PRs (including closed state), reviews, inline comments, commits, issue/PR comments, earlier verified runs with URLs, conclusions, artifact names and outcome contracts. Includes their outcome comments and available branch candidates; includes project-1 status for this issue and its current owned dispatch PR when present. Board reads use the separate board token, are tagged `github-api(project-1)` and untrusted, and degrade to `unavailable` on missing credentials or API failure. The query caps fields and each item’s project memberships at 100 and rejects truncated connections; responses are capped at 64 KiB. Includes the label/comment/review trigger verbatim and provenance. Optional sources degrade individually to `unavailable` with endpoint, HTTP status when available, and bounded redacted stderr; unverifiable authors remain `unverified`. Errors are request-scoped, deduplicated and tagged `github-api(error)` with `untrusted:true`. `sources` is a fixed response field retained when chronological context is clipped; `sources_omitted` reports overflow of its half-response budget. Only trigger/issue reads are mandatory. Two reads, bounded to 64 KiB; oldest items are dropped with a count, keeping the trigger. |
| `set_status {status}` | Three attempts. Accepts exactly `Todo`, `In progress`, `In review` or `Blocked`; Done stays with merges. The server freshly resolves only the admitted issue and its owned dispatch PR in org project 1. No item/project fields are accepted. Items absent from the board are left absent. An item with any other set status (including Done) is left alone and reported as `left: <status>`. Each confirmed mutation is recorded; a partial failure reports only confirmed changes and marks the board unavailable without failing the run. |
| `select_branch {branch}` | Before workers begin, selects the new run branch or an authenticated issue-linked branch. Reads and retains its remote tip for the publication lease. |
| `read_artifact {run, name}` | Reads one fixed text filename (`contract.json`, `handoff.json`, `raw.log`, `transcript.md`, `diffstat.txt`) from a completed earlier run. Verifies workflow/run/owner identity, a completed `carrick-agent` worker with successful upload, and the issue-derived upload bundle name. Review runs must keep the workflow blob from their head’s merge base with main. The returned contract, handoff or worker-transcript text is tagged with its dispatch provenance and marked untrusted. Rejects another issue, workflow, current run, expired/oversized bundle or unknown filename. Download is runner-private and the final read refuses symlinks and exceeds neither 64 KiB nor the event wall budget. |
| `read_capacity {}` | Runs pinned `agy_worker.py capacity --json` as the worker account. Reads the real `backends` map from `capacity_report`, with `installed`, `free_slots`, `quota_free`, `score` and agy `quota.groups`/`group_scores`. Augments it with exact current IDs from the launcher's live `models --backend` roster, excluding superseded IDs. Returns numeric capacity and model IDs only, never credentials or raw diagnostics. Only successful capacity reports are cached. Each admitted worker consumes its snapshot, so the next worker requires a fresh report; refused choices can reuse the current successful report. Total probes are capped at `workers + refused_workers`. Each subprocess/output is bounded (120 s, 64 KiB) inside the event wall budget. |
| `invoke_worker {notes, backend, model}` | Notes at most 8 KiB, with the model choice and reason. Checks remaining worker, tool-call and time budgets before consulting the cached capacity snapshot; refuses missing/uninstalled/full/exhausted backends and missing/exhausted models before charging either call or worker budget. Agy quota is checked for the selected model's group. Three refused worker requests exhaust their separate refusal budget without charging workers. Runs workers sequentially on the selected branch; each later worker sees earlier commits and a server-built handoff of contract summaries, tests and risks. All workers share 35 total minutes; owner trigger and inline review text are supplied verbatim, with coordinator notes separately labelled. |
| `publish {}` | Shared receipt/ownership checks; refuses `.github/workflows/*`; only the admitted branch, fixed refspec and expected-tip lease. Creates a draft with the first commit’s title or continues the owned PR. A worker can write `pr-body.md` beside `result.json`, outside its checkout, to propose a body (8 KiB, regular UTF-8 file, no symlinks). The server masks tokens, neutralises mentions with a U+2060 WORD JOINER, strips template instructions, refuses extra closing references and supplied run footers, then adds exactly one `Closes #N` line and its run footer. A refused proposal is reported with its reason and never blocks the commit push. The same body is used for creation or a REST `PATCH` on continuation. After each write, the server verifies closing references with the job token using the bounded consistency protocol below. An observed extra reference or persistent read error restores the default template on create, or the previous body on edit. A deadline alone keeps the locally validated new body and reports it as unverified. Both restorations are verified. Failure outcomes are posted on the PR, and an unverified restoration puts a manual repair warning first. The creation-run footer stays in the PR body to preserve branch ownership, and an edit ends with the current run footer. An earlier checkpoint’s proposal is passed to later workers for revision and retained when they write no proposal. With no proposal, creation fills today’s template and continuation leaves the body alone. Bodies remain untrusted dispatch-agent text in later reads. |
| `comment {body}` | At most 8 KiB; posts only on this issue or its continued PR, with token masking, credential redaction, mentions neutralised with a WORD JOINER and a verified run footer. |
| `finish {status, summary}` | `done`, `blocked` or `failed`; posts a human-readable outcome led by a markdown list of server-confirmed commits pushed (short SHAs), whether the body was created, updated, refused or left alone, and confirmed board changes or protected items left alone. Loop and worker statements are separately labelled as unverified claims; the loop summary is blockquoted and retained separately as `loop_summary` in `contract.json`. Raw contracts, backend/model choices and budgets sit in collapsed details. The full claims remain in artifacts. One attempt, exempt from call budget; failed posting stops the loop and triggers one server fallback. |

GitHub's closing-reference index updates asynchronously. After each create or
PATCH, the server waits three seconds, then requires two consecutive matching
reads at least two seconds apart. An unexpected extra reference fails immediately.
Each read gets one retry for a transient API failure. Each write's verification
has a twenty-second limit, including API time, and is bounded by the publish
command window. Primary publication reserves thirty seconds within that window
for restoration and its verification; recovery never extends the caller's budget.
A failed pre-edit snapshot skips the body update, names the refusal in the
applied report, and preserves the commit push.

A deadline alone, without an observed extra reference, leaves the locally
validated new body in place. The outcome reports `closing references unverified`
and says the body was kept, rather than calling the update successful. Other
verification failures attempt restoration and report its verification separately.
Recovery never turns the failed publication into a successful outcome.

Before an edit, the server snapshots all closing references and GitHub's
body-derived view (`excludeUserLinked: true`). The expected set is this issue
plus references present before the write that were absent from the old body's
reference set. This preserves manual owner links in the Development sidebar;
references from the old body are not treated as manual links. The comparison
includes both repository and issue number, so the write cannot introduce a new
closing reference in any repository. Both connections are bounded at 100 nodes;
truncated or malformed responses, and responses over 64 KiB, are unverifiable.

Before publication, the server applies the same conservative closing-keyword
filter to `merge-base(live main, HEAD)..HEAD`, excluding commits already
published on the branch before this run. Main and previously published history
are trusted. Closing this issue in this repository is allowed. A new worker
commit targeting another issue or repository refuses publication and names the
commit, so rebase landing cannot close an unrelated issue through its message.

Every PR body write (including restoration) and loop-authored post, including
the loop summary and worker-choice reasons,
inserts a WORD JOINER after mention-leading `@` characters. This works inside
HTML and code blocks. Numeric at-sign entities and `&commat;` are decoded before
neutralisation. An ASCII alphanumeric or underscore prefix leaves an address such as
`user@example.com` or `https://user@host` intact.

The server's observed result governs the outcome status. A failed, timed-out
or incomplete last worker, or a published HEAD created by the server as a
checkpoint, forces a failed outcome even when the loop requests done. A later
worker returning done does not validate an unchanged checkpoint. The server
records a failed result and its reason for every admitted worker whose setup,
fetch, review read, harvest, contract parsing or retirement fails.
Only the last admitted worker governs this floor; an earlier failed attempt
does not invalidate a later successful worker. The server
verdict and evidence appear first; the loop's claimed status and summary are
quoted below them. A successful worker that adds a normal commit on top of a
checkpoint clears the floor. The checkpoint commit remains in the published
history.

Fallback outcome contracts come only from authenticated server outcome comments,
never from PR bodies. `Outcome contract:` is reserved for those reports; body
proposals and the comment tool refuse the marker.

`[loop].loop_backend` and `[loop].loop_model` select the coordinator itself.
They are omitted from its event budgets and do not constrain workers. Worker
choice is the loop's own decision from `read_capacity` and task difficulty.
At publication the server resolves and fetches live main with its own token.
It lists `merge-base(live main, head)..head` as “PR commits”, marking commits
not reachable from the previous remote tip as “new in this run”. The same
base governs workflow-change refusal, so main's workflow edits are not
attributed to the worker. A rewritten branch reports “Rebased onto main at
<sha>”; merging main does not produce that claim.

The only ceilings are `[loop]` in `.github/dispatch-tiers.toml`: 12 tool calls,
two state reads, three workers, three refused worker requests, one publication,
two optional comments, three status updates, 64 KiB state, 42 wall minutes
including at most 35 total worker minutes. Each worker allocation includes `[loop].harvest_seconds`
(default 180 seconds): the agent deadline is that much earlier than the
worker deadline. Retirement, permission hand-back, snapshot, checkpoint and
result collection use the reserved window. A timed-out worker retains partial
work and logs with a failed timeout contract. Harvest failures name the original
error and discard the failed candidate. The last successfully harvested tree
and its receipt stay available for continuation and publication. The receipt
retains that worker's model, contract and exact HEAD; a mismatched tree and
receipt is refused. The PR body puts the human summary first, then the
published checkpoint's provenance, even after a later harvest fails. A failed
checkpoint install restores the previous pair, or invalidates the receipt if
rollback also fails. Without a valid
pair, publication is refused with a named reason. Production is never rerun as
a setup failure.
The reserve is deducted from worker and wall time, rather than added after
either budget. The 42-minute default leaves five minutes within the 47-minute
loop step for retirement and reporting. The workflow stamps
`CARRICK_DISPATCH_STEP_STARTED_AT` before acquiring the host lease; the working
window is capped at step start + 47 minutes - the five-minute final reserve,
so lease waits consume working time. Post-loop capture has its own 90-second
window within that reserve. If final capture fails after finish, the existing
contract, handoff and logs are re-masked and scanned for upload; scan failures
still disable upload. The loop also stops by job minute 55
to leave five minutes of the 60-minute job for finalization and upload. There
are no dispatch tier tables or tier-selected credentials. The loop chooses
from live capacity and explains its choice in the outcome. Capacity snapshots
expire after two minutes, including before the first worker, and each admitted
worker consumes its snapshot. No retries or
budget increases occur on refusals. If the loop exits or times out without
finishing, the server posts a failed fallback to the admitted issue/PR. Hard
cancellation or GitHub failure can prevent that network report.

Provenance is information, never authority. `owner` requires the owner User;
`dispatch-agent(run N)` requires a bot post with a verified last run footer,
repository, workflow, owner actors and a completed worker job on an agent
runner; comment and PR-body provenance survives artifact expiry or failed
uploads. Issue and comment footer runs additionally need exactly one successful
`Dispatch issue N` marker in their successful hosted guard job, matching the
admitted issue. The marker uses the validated issue number, including for PR
comments. Earlier runs without that marker have unverified footer text.
Issue and comment runs use main; review runs require their workflow
blob to equal the head’s merge-base blob. Available issue/PR mappings must
match; artifact reads additionally require an issue-scoped uploaded bundle. Commit authors never grant owner or collaborator provenance: commits
are tagged `commit(author-claimed)`, and their messages are withheld unless
their SHAs belong to an authenticated handoff’s published-tip parent chain.
Deleted or invalid linked runs are skipped. History discovery retains all
known run IDs from linked branches and comment footers. An additional census
of at most 32 completed issue/comment runs of this workflow after issue
creation checks issue-derived artifact-name prefixes before authenticating
runs; it never scans the repository-wide artifact inventory. Each server
caches authenticated runs, artifact listings and downloaded text, including
confirmed predicate refusals. Lookups and downloads get at most three attempts
per cache key and event, one attempt per call so later calls can recover from
an outage. Transport failures are never cached as predicate refusals.
Unchanged branch selections reuse history verification while rechecking live
remote tips and all-state PR ownership before admission or publication. Contracts from verified
artifacts take precedence over comment previews, and the server’s outcome
block precedes all model text. Write collaborators are tagged
`collaborator(login)`; all others are `unverified`, with bodies withheld. Lookups are cached. No provenance tag can
widen tool permissions. Admission is bound to the webhook digest in private
runner state; auth and the loop consume it without reinterpreting labels.

Output is token-masked and scanned before upload: `raw.log`, `transcript.md`,
`contract.json`, `handoff.json`, `diffstat.txt`, `loop.log`,
`loop-transcript.log` and optional `pr-body.md`, retained 30 days after successful or failed loop outcomes once uid retirement and artifact scanning succeed. The final contract and handoff persist each worker's claims and publication context for future runs; runs share no local state. Unknown or nonregular
files are refused. `loop.log` is capped at 64 KiB and records tool selectors,
text lengths (never note or comment bodies), outcomes and durations, plus
GitHub source, capacity, worker and harvest phase timings. It keeps opening
context and recent records, marking dropped older diagnostics. The loop's
foreground event log, stderr, stdout and available final launcher response are
saved as JSON sections in `loop-transcript.log`, with an independent fixed
serialized byte share for each stream. Model text cannot forge section framing
or crowd stdout/stderr out. The full transcript is capped at 512 KiB. Redaction precedes
clipping and the token scan covers every uploaded file, including diagnostics
written by the final outcome post. The workflow uploads
the whole `dispatch-output` directory, including these diagnostics. Worker contracts are claims for review; incomplete contracts
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

### Pinned GitHub CLI

The template pins official GitHub CLI release 2.102.0 (SHA-256 verified) at
`/usr/local/bin/gh` rather than installing Debian's apt package, so `gh api
--slurp` is available for dispatch review continuation and comment pagination
(#838). Template qualification verifies `gh --version` reports 2.102.0 and
`gh api --help` lists `--slurp`.

## Rollout and live acceptance

Portable tests cover trigger trust, capacity refusal without charges, branch
ownership, publication, socket/environment isolation and workflow wiring. They
cannot establish deployed acceptance. The director must push from the Mac
(App tokens cannot push workflow edits), deploy the new controller and verify
agent-template accounts/tools and the pinned launcher roster/capacity APIs.
For #833 rollout, add the Mac publish-token minter with the repository and
permissions above. Verify that both a new dispatch PR and a continuation push
start CI for their current head without an owner push or ready event.
For #811/#842 rollout, add the Mac board-token minter, then verify a trial
reads both board items and changes only those items through the scoped tool.
Continue an owned PR with a worker-proposed body and check the live body,
exactly one closing line, outcome action list and retired model uids. These live
checks require the deployed workflow and credential; portable fixture tests do
not establish them.
Then label #587 as written with `dispatch`, observe a draft PR, request changes
as owner, and observe a new commit on that PR branch plus an outcome comment.
Exercise `/agent` on an issue and a merge-conflicted owned PR, verify refusal
of edited/non-owner comments and an unowned PR, and confirm both model uids
retired. These trials also complete #799's pending live acceptance.
