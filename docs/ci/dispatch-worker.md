# Collaborator-triggered dispatch (#797, #799, #800, #1214)

Every trigger enters one agent loop on an owner's `[carrick-agent]` disposable
JIT clone. The controller caps the pool at four clones; the job cap is 85
minutes. Clones are destroyed after every job, including failure and timeout.
VM-local leases and template 9000 remain as in [Contabo setup](contabo-kvm.md).

## Admission and scope

Any repository collaborator with write access or higher (a human account,
type `User`) can start a run by (owner decision recorded on #231, #1214):

- Applying `dispatch` or any `dispatch:*` label to an open issue. The issue
  can have any author, including the carrick-workers App. The suffix is
  free-text context for the model, never a model selector.
- Creating an unedited `/agent [free text]` comment on an open issue or an
  owned dispatch PR, including a merge-conflicted PR.
- Submitting a `changes_requested` review on an owned dispatch PR.

Trust is checked live. The guard, clone admission, the controller and the
token mint read `GET repos/carrick-sh/carrick/collaborators/{login}/permission`
for the sender, the triggering actor, the comment or review author and, for
workflow runs, the run's actor and triggering actor. Only `admin`, `maintain`
and `write` are accepted; `read`, `triage`, `none`, a malformed login, a 404
and any API error are refused. The workflow's `if:` is only a cheap
pre-filter: comment and review triggers need an `OWNER`, `MEMBER` or
`COLLABORATOR` author association, and label events already need triage
access to apply a label. A trusted actor's label, comment or review is the
approval, so the issue or PR author no longer matters. A comment must have
identical creation/update timestamps, match `/agent` followed by whitespace or
end-of-body, and still match the original webhook when admission fetches it.
Edited events and triggers from anyone without write access are refused.

The approval covers only issue text a collaborator saw or wrote. On every
path that admits an issue (label, `/agent` on the issue, `/agent` or a review
on an owned dispatch PR, and adoption), the guard and clone admission read the
issue's `title` and `body` in one GraphQL query together with `lastEditedAt`,
`editor`, and the latest `RENAMED_TITLE_EVENT` timeline item, and populate
`Dispatch.title` and `Dispatch.body` from that response. The body is accepted
only if it was never edited since filing, or its last human editor passes the
same live write check; otherwise the round is refused with "issue body was
last edited by a non-collaborator; a collaborator must edit or re-file it".
Because `lastEditedAt` tracks body edits only, the title is checked separately
against the rename timeline and accepted only if the issue was never renamed,
or the latest rename matches the current title and its human actor passes the
same live write check; otherwise the round is refused with "issue title was
last edited by a non-collaborator; a collaborator must retitle or re-file it".
GraphQL errors, title mismatches and missing fields are refused too. The guard
never parses issue structure. The
loop reads the full issue, so #587's problem statement and acceptance need no
special heading. Unclear work can finish blocked with a question for the requesting collaborator.

For issue work, the server starts `work/dispatch-<issue>-<run>`. The loop can
select another linked `work/dispatch-*` branch before invoking workers. A
candidate must have an open owned dispatch draft PR closing this issue, or an
authenticated earlier run's handoff recording its publication. The server
verifies the original run, workflow, collaborator identities and issue-scoped artifact
name, then reads the live remote tip. Without an open PR, the tip must equal
the latest authenticated handoff publication for that branch. A branch with
any closed or merged PR is refused. Reviews stay on the reviewed branch and
cannot call `select_branch`. A suggestive branch name alone grants no
authority. Other issues' branches, non-dispatch names and unlinked branches are
refused. The explicit `select_branch` tool is the sole request schema with a
branch field; no schema has issue, PR, repository or scope fields. PR triggers
start on their owned branch and require an open linked issue.
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
the comment and issue/PR independently, checking the collaborator, command, unedited
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

### Adopting a director PR (#1175)

Dispatch can also continue a PR it did not open, such as a director session's
`work/986-slice4`. A collaborator adopts it for one round by commenting
`/agent` on the PR, with the same unedited-comment and live-permission rules as
above. Adoption needs
all of these, checked against the live PR when the comment is admitted:

- The PR is open, its head branch is in this repository, and it targets
  `main`.
- The head branch is a valid `work/*` name that is not a
  `work/dispatch-<issue>-<run>` name. Dispatch-named branches always take
  the owned-PR path above.
- GitHub lists exactly one closing issue for the PR (`Closes #N` in the body
  or a sidebar link), and that issue is an open issue in this repository. It
  becomes
  the run's issue: the loop reads it, the board updates it, and commits may
  close only it.

The PR head the hosted guard observes becomes the admitted tip. That is the
head when the guard runs, not when the comment was written: runs for one PR
wait in a concurrency queue, so a push made while the run is queued is adopted
under the collaborator's comment. Clone admission and the controller refuse a
different head, as for owned PRs. The run can push only to the adopted
branch, with `--force-with-lease` set to that tip, and it cannot call
`select_branch`. If someone pushes to the PR after the guard, the run pushes
nothing, reports why and ends blocked; comment `/agent` again to continue
from the new head. The controller also checks that the issue the guard named
in its `Dispatch issue` step is the one it resolves itself.

The director owns the adopted branch's history. Workers add commits on top of
the admitted tip and never rebase or rewrite it, unless the director consents
(owner decision, #1215). Consent is a line that is exactly `Rebase: allowed`
in the admitted `/agent` comment, from the owner account (which director
sessions post as); a write collaborator's trigger cannot consent. The guard
records it as `Continuation::Adopted.rebase`, the coordinator sees it in
`read_state` as an `adoption` item (`rebase_allowed`), and the worker brief
asks for a rebase onto admitted main. Publication then accepts a HEAD that
descends from admitted main instead of the admitted tip, pushes it only under
the same `--force-with-lease` that starts at the admitted tip, and reports
"Rebased onto main". The rebase must keep the director's history:
- the director's non-merge commits from the merge-base with main to the
  admitted tip come first above admitted main, in order, each with the same
  author email and the same full message (so none gains a closing keyword);
  commits main already has (`git cherry` `-`, never an empty commit) count
  as kept;
- none of them is replaced by an empty commit, every path they changed is
  changed by the rebased director commits or already matches, and the
  rebased director commits change only paths the director's own commits
  changed (conflict resolution stays within them); anything else would be
  the run's own work hidden from its checks. Each commit's author and
  message are read individually, never parsed out of one log stream;
- a commit whose patch changed while resolving conflicts is allowed and
  listed in the outcome, with a `git range-diff -s` summary of the director's
  commits before and after.

Otherwise nothing is pushed. The run's own commits start above the rebased
director tip, so main's commits between the fork point and admitted main
(their workflow changes and closing keywords) are never charged to the round,
and neither are the director's. Without consent, or when a rewritten HEAD descends from
neither, the run pushes nothing and ends blocked. Workflow-file and closing-reference checks
count only the run's own commits (admitted tip to HEAD), never the
director's.

On an adopted PR dispatch pushes commits and nothing else. It never creates a
PR, edits the body or changes draft status; a worker's proposed PR body is
refused and the outcome says so. The outcome comment goes on the PR with the
usual run footer. One predicate, `adopted_pr` in
`crates/carrick-xtask/src/dispatch_worker.rs`, makes this decision for the
guard, clone admission, the controller and the loop. The PR's author is not
checked: a same-repository head already needs write access, and the trusted
`/agent` comment is the approval. Reviews (`changes_requested`) on adopted PRs
are not supported yet.

### Reactor (#1193)

`carrick-xtask dispatch-worker reactor once|run` runs on the owner's Mac as the
owner's user and watches PR conversation so the owner does not have to type
every `/agent`. Each cycle (`run` repeats every 60 s) reads open PRs, issue
comments, PR review comments and reviews newer than a cursor, then asks a
local agent (`claude -p`, model `--model`, default `sonnet`) for one JSON
decision per PR with new events: `ignore`, `reply` or `round`.

The agent only proposes; code decides what is posted, as the owner's `gh`
login, with the hidden marker `<!-- carrick-reactor -->`:

- A `round` posts `/agent <brief>`, which the dispatch guard admits as an
  unedited comment from the owner, a write collaborator. The reactor itself
  stays owner-local: it watches only PRs opened by the owner or the
  carrick-workers App, though adoption no longer checks the PR author. It is posted only when the PR passes `adopted_pr`
  or is an owned dispatch PR, no `dispatch-worker.yml` run is queued or in
  progress for that PR, and fewer than four dispatch runs are in flight.
- At most one reactor round per PR head, and at most three in a row,
  unless an owner comment arrived after the last reactor round. A round
  pushes a new head, so the second limit is what stops a red CI, round, red
  CI loop. State records the round's head, time and count.
- A `reply` posts plain text; text starting with `/agent` is refused.
- Dispatch outcome comments (from `github-actions[bot]` or
  `carrick-workers[bot]`, containing "Dispatch outcome") are events, so a
  finished, blocked or failed round gets a decision. Other bot comments and
  comments carrying the marker are not. Owner `/agent` commands do not ask
  for a decision but count as a human comment. PRs labelled `agent:hold` are
  skipped.
- Every open PR is in scope, however old: the reactor exists to finish PRs.
  Label a PR `agent:hold` to keep the reactor off it. In `run` mode a
  director PR without exactly one closing reference gets one reply asking
  for `Closes #N`, and an adoptable PR with no push for 15 minutes and no
  reactor round yet counts as one event per head.
- Each poll reads the repository and organization interaction limits and
  logs a warning when either is not `collaborators_only`, cannot be read, or
  expires within 30 days. GitHub caps a limit at six months, so renew both:
  `gh api -X PUT orgs/carrick-sh/interaction-limits -f limit=collaborators_only -f expiry=six_months`
  and the same on `repos/carrick-sh/carrick`.
- The reactor never merges, pushes, edits, labels or closes anything.

State (cursor and per-PR memory) lives in
`~/Library/Application Support/carrick-reactor/state.json`, or `--state`.
`--dry-run` prints decisions and would-be comments, posts nothing and leaves
the state unchanged. A launchd agent keeps it running:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>sh.carrick.reactor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Volumes/CaseSensitive/carrick/target/debug/carrick-xtask</string>
    <string>dispatch-worker</string><string>reactor</string><string>run</string>
  </array>
  <key>WorkingDirectory</key><string>/Volumes/CaseSensitive/carrick</string>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/Users/tjfontaine/.local/bin</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Users/tjfontaine/Library/Logs/carrick-reactor.log</string>
  <key>StandardErrorPath</key><string>/Users/tjfontaine/Library/Logs/carrick-reactor.log</string>
</dict>
</plist>
```

Save it as `~/Library/LaunchAgents/sh.carrick.reactor.plist` and load it with
`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/sh.carrick.reactor.plist`.

#### Session mode

Session mode replaces the one-shot `claude -p` decision with a long-running
Claude Code session that keeps one subagent per PR. It has two parts:

- `dispatch-worker reactor feed [--mailbox P] [--state P] [--once]` runs
  the same poll with no decision step. It appends one JSON line per new
  event to the mailbox: `{id, pr, kind, author, url, created_at, head,
  excerpt}`, where `kind` is `comment`, `review`, `review_comment`,
  `outcome`, `ci_run`, `ci_job`, `new_pr`, `quiet_pr` or `needs_closes`. The feed
  only reports facts; the session judges them. `ci_run` is any completed
  Actions run on a director or owned PR's current head, whatever its
  conclusion (`dispatch-worker.yml`'s own runs report through outcome
  comments). Runs are read from `actions/runs?status=completed`, created up
  to three hours before a separate run cursor. `new_pr` and `needs_closes`
  fire once per director PR, and `quiet_pr` once per quiet head on a
  director or owned PR, however old. Its state file is separate from
  `run`'s.
- `dispatch-worker reactor mcp [--state P] [--dry-run]` is a stdio MCP server.
  Its read tools are `read_pr`, `read_thread`, `read_diff`, `read_ci`,
  `read_outcomes` and `read_issue`. Its only act tools are `reply` and
  `request_round`, and both go through the same `enforce` gates as `run`.
  The server records round heads and times in its own state file and
  re-checks for a later owner comment live before allowing another round on
  the same head. `reply` needs a trusted PR (the owner's or the publish
  App's) and an owner event since the reactor's last reply on it, so there
  is one reply per owner message. Replies are capped at 2000 characters and
  briefs at 4000, and text containing a credential prefix (`ghp_`, `ghs_`,
  `github_pat_`, `-----BEGIN`, `AKIA` and the like) is refused. A round
  posted in the last ten minutes counts against the global cap until its
  run is listed. `read_ci` keeps only Actions runs of this repository on
  the PR's head SHA, since a fork PR can share the SHA and name its own
  jobs, and an untrusted PR shows no CI, title, branch or closing
  references at all.
- `ci_job` reports a job that failed, was cancelled or timed out while its
  run is still in progress (`actions/runs?branch=&status=in_progress`, then
  the run's jobs), once per job and attempt, for this repository's runs on
  the PR's head. So a broken build is visible before the whole run and
  `ci-ok` finish; the run's `ci_run` still follows.
- Long `wait_events` calls run as Claude Code background tasks (any
  main-session MCP call over 120 s, `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS`,
  pinned in `start.sh`): the session ends its turn and the task's
  completion wakes it. A wait lasts up to 25 minutes, under the 30-minute
  stdio idle abort, or up to an hour when the call carries a
  `progressToken`, with `notifications/progress` every 5 minutes. Read tools
  carry `readOnlyHint`, so they can run in parallel. `read_diff` returns at
  most 40,000 characters, below the 50,000 at which Claude Code saves a
  result to a file the session can't open. The `pr-watcher` subagents run
  on Sonnet (owner decision, #231).
- Events reach the session through the `wait_events` tool, which follows
  the mailbox (`--mailbox`) and returns new lines; the last delivered id is
  kept in `--channel-state`, so a restart doesn't redeliver. With
  `--channel` the server instead declares `experimental["claude/channel"]`
  and pushes each line as a `notifications/claude/channel` message. That
  needs `claude --dangerously-load-development-channels
  server:carrick-reactor`, which asks for confirmation on every launch, so
  the deployed session doesn't use it.

The repository is public, so only the owner (`tjfontaine`, type User, which
director sessions post as) can produce events, count as a human comment for
the loop guard, or have comment, review, PR and issue bodies shown to the
session. Dispatch outcome comments from the workflow bots are the only other
events. Anyone else's comment shows as `{author, created_at, untrusted:
true}`, and diffs and CI logs of other authors' PRs are withheld.

`scripts/reactor/` holds the session workspace files: `prompt.md` (the
routing role, appended to the system prompt), a `pr-watcher` subagent
(`agents.json`), `mcp.json`, permission settings and `start.sh`. They are
copied to `/Volumes/CaseSensitive/carrick-director/reactor/`, outside any
checkout, and the mailbox and state files live in its `state/` directory.
`start.sh` starts the session as `carrick-reactor` in the tmux session of
the same name, in the repository checkout; the feed runs as its own
launchd job. The session has no file tools: Read, Glob and Grep are
denied, and user hooks are off (`disableAllHooks`).

The reactor and the director session (`carrick-director`) agree on actions
over Claude Code's SendMessage. At start the reactor reads AGENTS.md and the
decision log (#231, through `read_issue` with `comments`), tells the
director what it takes the priorities to be, and keeps the director's
correction as the working agreement. PR subagents end a turn with a
`proposal:` line (the action, who does it, why); the router batches and
orders them by priority and sends one message. Reactor actions wait for the
director's agreement, except a reply to the owner's direct question and a
round the owner asked for on GitHub. The director weighs proposals against
its own goals and answers, and can message `carrick-reactor` about a PR,
the priorities or status. The tool gates apply to every reactor action, and
for the director a reactor message is a report to check, not an
instruction.

## Accounts and credentials

The runner holds the job-scoped `GITHUB_TOKEN` with exactly `contents: write`,
`pull-requests: write`, `issues: write` and `actions: read`. The tool server
alone uses it for GitHub reads, comments, closing-reference checks and run
lookups. Publication also uses it when the publish credential is unavailable.

The publish and board tokens are one-hour `carrick-workers` App installation
tokens that the standing ctb controller mints when the tool server needs one
(#1012). They are not repository secrets, and no workflow step receives them.
Minting on demand means a job that waited in the runner queue, or a turn that
runs close to an hour, still writes with a fresh token.

How a token is requested:

1. Right before its first publication write, or its first board read or
   update, the runner-uid tool server writes a request (`publish` or `board`,
   a random nonce, and the run, attempt and SHA from the root-owned
   `approved-policy`) into `/run/carrick-ci/token-request`.
2. The controller reads the request through the scoped PVE guest agent. It
   checks that the runner is a running agent clone it approved for this exact
   run and attempt, that GitHub reports the assigned `worker` job of
   `dispatch-worker.yml` in progress on that runner at that SHA, and that the
   job has mint budget left (six tokens per scope, 32 answered requests per
   clone). The ledger records each answered nonce before any mint, never the
   token.
3. The controller signs an App JWT with the key from its systemd credential
   and mints a token with a fixed grant. The grant comes from the controller,
   never from the request. `publish` is
   `{"repositories":["carrick"],"permissions":{"contents":"write","pull_requests":"write"}}`.
   `board` is `{"permissions":{"organization_projects":"write"}}`. It rejects
   a minted token unless it has every requested permission at exactly the
   requested level; the only extra it accepts is the `metadata: read` that
   GitHub adds to repository grants.
4. The answer goes back as stdin of a root shell in the clone (never in a
   command line) into `/run/carrick-ci/token-response`. That file is runner-owned
   0600 in a root-owned directory, so the model accounts cannot read it and the
   runner cannot swap it for a link. The tool server reads it and erases it at
   once, then keeps the token only in memory for at most 45 minutes. The
   controller revokes every token it minted for the clone once the job ends.

The tool server waits at most 60 seconds for an answer. If the controller
refuses, the channel is missing (any runner other than a ctb agent clone), the
runner has no approved `agent` policy or no answer arrives, publication uses
the job token. The artifact records why in `token_fallback`: `mint_refused`
with the controller's reason (for example `budget_exhausted` or
`job_not_in_progress`) or `mint_unavailable` (`no_channel`, `no_assignment`,
`timeout`, `malformed`). The outcome comment states the same reason. The board
reports `unavailable` with that reason, and the run continues. The tool server
remembers a decided refusal (identity mismatch, no assignment, scope, invalid
request, finished job, exhausted budget) for 45 minutes. It asks again after
five minutes when the channel was unavailable, the mint failed or the
controller had no key, so a down controller costs one bounded wait per
interval. Requests from one process are serialized, because they share one
request file and one response file.

The tool server uses the publish token only for the fixed-refspec branch push
and PR creation or body PATCH, including restoration, and the board token only
for project-1 reads and status updates of the dispatch issue and PR. Git and
GitHub subprocesses receive a token as `GH_TOKEN` only for those calls; reads,
comments, closing-reference checks and run lookups keep the job token. Both
model accounts receive cleared environments. Diagnostic redaction and the
complete artifact scan cover every token the process minted, and every
installation token by its `ghs_` shape. No App private key enters a clone or
GitHub Actions. The App has no workflow permission, so dispatch continues to
refuse workflow file changes and reports an App push refusal explicitly.

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
the same evidence resolver. The credential-free hosted guard reads public
PR comments first, then issue comments, in pages of 100 and up to five pages
per destination. A valid receipt from any successfully read page is enough.
A failed, malformed or oversized page stops that destination without
invalidating receipts from earlier pages; reaching the cap also retains them.
The loop, token-bearing admission step and controller independently resolve
ownership with authenticated artifact and comment reads; the guard's proof
is not reused at admission. If an earlier run pushed a branch but never
created its PR, a later run creates that PR with the job token: it cannot add
an App publication binding to the original run's immutable artifacts.

If no publish token can be minted, publication uses the job token. An
authentication failure from an App push, PR create or body PATCH retries
that operation once with the job token and keeps the job token for the rest
of publication, including restoration. Bad credentials, HTTP 401 and Git's
authentication or missing-username errors qualify. Lease rejections, network failures and 403
workflow or permission refusals do not retry. The outcome says CI won't start
automatically and asks a person to mark the PR ready only after a push or PR
write actually happened, unless an App push to an existing PR or an App PR
creation already triggered CI. A push before a PR exists does not count as a
PR synchronize event. Falling back does not fail the run.

The dedicated nologin accounts `carrick-dispatch-loop` and
`carrick-dispatch-agent` have distinct uids and groups, no sudo rights and no
runner group membership. The runner joins their groups and can sudo only to
those accounts, never root. Runner-owned 0700 state holds the driver, artifacts
and `redaction-secrets.json`. Model processes get `private_environment`, no
GitHub tokens, Actions command files or runner environment. The Unix tool socket
accepts only the loop uid through Linux `SO_PEERCRED`, refusing the worker uid.

Bootstrap fetches the pinned launcher from private `carrick-sh/agy-director`
with a `bootstrap` App token that the ctb controller mints on demand, like
publish and board tokens (#1034). Its fixed grant is `contents: read` on that
one repository, one mint per job, held in the controller ledger and revoked
when the clone is reaped. A refused or unanswered request fails bootstrap; no
other token is tried. The workflow provisions every available
worker credential: `CODEX_AUTH_JSON` and `AGY_OAUTH_TOKEN`. Worker-private homes
contain only the selected backend’s credential subtree. The runner-private
capacity-query home retains both; the separate loop home holds only agy auth.
Codex can be absent; agy is required for the loop. These repository secrets are referenced only by
`dispatch-worker.yml`, enforced by workflow tests. The owner's Mac still
pushes these two long-lived secrets; it no longer supplies any App token to
the workflow.

A model can read its own provider credential, including its refresh token,
and the pinned launcher. This is residual exposure, not a hardened secret
boundary. The private launcher is not secret (owner decision #231). Trusted
bodies can still misdirect a credential-bearing model. The collaborators-only
interaction limit expires on 2027-04-04 and is not a lasting trust boundary.
Earlier jobs capped exposure at 40 minutes; the current window reserves time
for bootstrap, a 67-minute loop and reporting. Publish and board tokens are
minted on demand, so the job's length is not bounded by a token read at
admission (#1012). The job token can write branches belonging to other runs: the uid split and fixed refspec enforce normal scope, not its
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
| `read_state {}` | Full issue and linked dispatch PRs (including closed state), reviews, inline comments, commits, issue/PR comments, earlier verified runs with URLs, conclusions, artifact names and outcome contracts. Includes their outcome comments and available branch candidates; includes project-1 status for this issue and its current owned dispatch PR when present. Board reads use the separate on-demand board token, are tagged `github-api(project-1)` and untrusted, and degrade to `unavailable` on missing credentials or API failure. The query caps fields and each item’s project memberships at 100 and rejects truncated connections; responses are capped at 64 KiB. Includes the label/comment/review trigger verbatim and provenance. Optional sources degrade individually to `unavailable` with endpoint, HTTP status when available, and bounded redacted stderr; unverifiable authors remain `unverified`. Errors are request-scoped, deduplicated and tagged `github-api(error)` with `untrusted:true`. `sources` is a fixed response field retained when chronological context is clipped; `sources_omitted` reports overflow of its half-response budget. Only trigger/issue reads are mandatory. Two reads, bounded to 64 KiB; oldest items are dropped with a count, keeping the trigger. |
| `set_status {status}` | Three attempts. Accepts exactly `Todo`, `In progress`, `In review` or `Blocked`; Done stays with merges. The server freshly resolves only the admitted issue and its owned dispatch PR in org project 1. No item/project fields are accepted. Items absent from the board are left absent. An item with any other set status (including Done) is left alone and reported as `left: <status>`. Each confirmed mutation is recorded; a partial failure reports only confirmed changes and marks the board unavailable without failing the run. |
| `select_branch {branch}` | Before workers begin, selects the new run branch or an authenticated issue-linked branch. Reads and retains its remote tip for the publication lease. |
| `read_artifact {run, name}` | Reads one fixed text filename (`contract.json`, `handoff.json`, `raw.log`, `transcript.md`, `diffstat.txt`) from a completed earlier run. Verifies workflow/run identity with live collaborator actors, a completed `carrick-agent` worker with successful upload, and the issue-derived upload bundle name. Review runs must keep the workflow blob from their head’s merge base with main. The returned contract, handoff or worker-transcript text is tagged with its dispatch provenance and marked untrusted. Rejects another issue, workflow, current run, expired/oversized bundle or unknown filename. Download is runner-private and the final read refuses symlinks and exceeds neither 64 KiB nor the event wall budget. |
| `read_capacity {}` | Runs pinned `agy_worker.py capacity --json` as the worker account. Reads the real `backends` map from `capacity_report`, with `installed`, `free_slots`, `quota_free`, `score` and agy `quota.groups`/`group_scores`. Augments it with exact current IDs from the launcher's live `models --backend` roster, excluding superseded IDs. Returns numeric capacity and model IDs only, never credentials or raw diagnostics. Only successful capacity reports are cached. Each admitted worker consumes its snapshot, so the next worker requires a fresh report; refused choices can reuse the current successful report. Total probes are capped at `workers + refused_workers`. Each subprocess/output is bounded (120 s, 64 KiB) inside the event wall budget. |
| `invoke_worker {notes, backend, model}` | Notes at most 8 KiB, with the model choice and reason. Checks remaining worker, tool-call and time budgets before consulting the cached capacity snapshot; refuses missing/uninstalled/full/exhausted backends and missing/exhausted models before charging either call or worker budget. Agy quota is checked for the selected model's group. Three refused worker requests exhaust their separate refusal budget without charging workers. Runs workers sequentially on the selected branch; each later worker sees earlier commits and a server-built handoff of contract summaries, tests and risks. All workers share 60 total minutes; trusted trigger and inline review text are supplied verbatim, with coordinator notes separately labelled. |
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

Every outcome on a PR carries a "Server checked" line: the commits this round
pushed (from the worker checkpoint against the admitted tip), how many
commits the PR head is behind `main` (the compare API) and whether GitHub
reports a conflict (`mergeable`). A fact the server cannot read is reported
as unknown and changes nothing. When the coordinator finishes done but the
round pushed nothing and the PR is behind or conflicting, the outcome is
Blocked with those facts (#1215: a rebase round once reported Done on a PR
108 commits behind and in conflict). Otherwise the coordinator's own
judgement stands, so answer-only and review-only rounds can still be done.

When the coordinator ends without `finish` before its first tool call, the
fallback outcome says it is an infrastructure failure: no work was
attempted, so it says nothing about the requested work. Only the pinned
launcher's own `agy-worker:` diagnostic line is quoted; the rest of its
stderr stays in the masked artifacts. A timeout, or an exit after the
coordinator called a tool, keeps the plain reason.

Fallback outcome contracts come only from authenticated server outcome comments,
never from PR bodies. `Outcome contract:` is reserved for those reports; body
proposals and the comment tool refuse the marker.

The coordinator launches with a model tier, which the pinned launcher
resolves through the live `agy models` roster. When that lookup fails (it
timed out at 60 s in run 41165350388, #1240), the launcher uses its last
cached roster, then the seed roster pinned beside it in
`scripts/ci/inputs/agent-tools.json` (`agy_models_seed`, staged as
`director/agy-models-seed.json` and named by `AGY_MODELS_SEED` for the
coordinator, the workers and the capacity probe). A fresh clone has no cache,
so the seed is what keeps a slow lookup from ending the round. Refresh the
seed when the agy pin or the account's models change.

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
two optional comments, three status updates, 64 KiB state, 67 wall minutes
including at most 60 total worker minutes. Each worker allocation includes `[loop].harvest_seconds`
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
either budget. The 67-minute default leaves five minutes within the 72-minute
loop step for retirement and reporting. The workflow stamps
`CARRICK_DISPATCH_STEP_STARTED_AT` before acquiring the host lease; the working
window is capped at step start + 72 minutes - the five-minute final reserve,
so lease waits consume working time. Post-loop capture has its own 90-second
window within that reserve. If final capture fails after finish, the existing
contract, handoff and logs are re-masked and scanned for upload; scan failures
still disable upload. The loop also stops by job minute 80
to leave five minutes of the 85-minute job for finalization and upload. There
are no dispatch tier tables or tier-selected credentials. The loop chooses
from live capacity and explains its choice in the outcome. Capacity snapshots
expire after two minutes, including before the first worker, and each admitted
worker consumes its snapshot. No retries or
budget increases occur on refusals. If the loop exits or times out without
finishing, the server posts a failed fallback to the admitted issue/PR. Hard
cancellation or GitHub failure can prevent that network report.

Provenance is information, never authority. `owner` requires the owner User;
`dispatch-agent(run N)` requires a bot post with a verified last run footer,
repository, workflow, collaborator actors (live write permission) and a completed worker job on an agent
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

## Live transcripts (#1229)

While a round runs, the step log shows the coordinator's and each worker's
output as it is written, so a round can be watched instead of read from its
artifacts afterwards. Lines are prefixed `[loop]`, `[loop stderr]`,
`[worker <backend>/<model>]` or `[worker ... stderr]`.

The repository and its run logs are public, and a live line skips the
artifact scan, so:
- each batch of complete lines goes through `agent_loop::masked`, the same
  masking artifacts get (the job token, minted tokens, credential files and
  credential shapes), before it is printed; a partial line waits for its
  newline;
- control characters are removed, lines are capped at 2000 characters, and
  every printed line starts with its `[label]`, so model text can't start a
  line with a workflow command (`::add-mask::`, `::stop-commands::`, `##[`);
- the output files are created by the server (`O_NOFOLLOW`, truncated) and
  read through that same open file, never reopened by name, so an agent
  can't swap the path for a link to another file.

The serve loop that waits on the coordinator and on every worker pumps the
stream every 100 ms. The artifacts remain the record. Set
`CARRICK_DISPATCH_LIVE_LOG=0` to turn streaming off.

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
For #1012 rollout, load the App key as the controller's `dispatch-app-key`
credential ([contabo-kvm.md](contabo-kvm.md#dispatch-app-key)) and redeploy the
controller. Verify that both a new dispatch PR and a continuation push start
CI for their current head without an owner push or ready event, and that the
journal shows one `minted a publish token` line per publication. Then verify a
trial reads both board items and changes only those items through the scoped
tool.
Continue an owned PR with a worker-proposed body and check the live body,
exactly one closing line, outcome action list and retired model uids. These live
checks require the deployed workflow and credential; portable fixture tests do
not establish them.
Then label #587 as written with `dispatch`, observe a draft PR, request changes
as owner, and observe a new commit on that PR branch plus an outcome comment.
Exercise `/agent` on an issue and a merge-conflicted owned PR, verify refusal
of edited comments, comments from read-only or non-collaborator accounts and an unowned PR, and confirm both model uids
retired. These trials also complete #799's pending live acceptance.
