# Issue-label dispatch (#634, #733)

Only the owner, account type `User`, may label or rerun an owner-authored issue.
The hosted guard, driver and clone controller enforce admission and the
checked-in `dispatch:<tier>` allowlist. The worker runs on `[carrick-agent]` in a
one-job disposable JIT clone. The controller caps the pool at four clones;
the worker job has a 40-minute cap. Clones are destroyed after every job,
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
`carrick-sh/agy-director` launcher. Only the selected tier's `CODEX_AUTH_JSON` or
`AGY_OAUTH_TOKEN` reaches the auth step; the other provider secret is neither
materialized nor captured. The selected provider credential is intentionally
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

For at most 40 minutes, the job token can write issues/PRs and any
`work/dispatch-*` branch, including branches belonging to other runs. Driver
branch selection narrows normal publication, not the token's repository grant.
Ruleset 25522481 is disabled. Branch scope currently rests on the uid boundary
and the driver’s fixed refspec. Tag ruleset 25523683 is active. The issue
must be owner-authored, but collaborators may have edited its brief before
labeling; the owner must review it. Provider credential trust and review of
agent changes remain necessary.

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
The only runner sudo grant targets `carrick-dispatch-agent`; runner cannot
become root and the agent has no sudo rights. Portable tests
cover workflow selection, permissions, auth custody, H1 and branch policy. They do not establish
live deployed acceptance. The post-landing default-branch trigger and fresh-clone
trials remain with the director under #634.

Runner belongs to the agent's private group; the agent never belongs to the
runner group. After verified retirement, the driver reads agent files only
as data. It never executes or sources agent-written scripts, Git hooks or
configuration. Git runs against a reconstructed snapshot with hooks and
configuration disabled, never by changing into the agent tree to run commands.
