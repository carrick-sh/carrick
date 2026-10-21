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
`pull-requests: write`, `issues: write` and `checks: write`. Workflow steps use it
for continuation admission, pushing the assigned branch, and reporting results.
There is no long-lived write token, publisher job, bundle transfer, repository
credential gate, agent UID split or separate dispatch environment.
Draft-PR review and the repository gates establish content correctness.

`AGENT_DIRECTOR_TOKEN` remains a bootstrap-only **read** credential for the
pinned private `carrick-sh/agy-director` launcher. It is supplied only to the
bootstrap step before agent execution; dispatch does not depend on the Mac's
App-token refresher. The job token cannot read that separate private repository.
The existing digest-pinned codex, agy and just bootstrap remains in place.
Provider credentials (`CODEX_AUTH_JSON`, `AGY_OAUTH_TOKEN`) are materialized only
for the selected tier, in 0600 files in the private 0700 home. Cleanup removes
provider, launcher and worktree state after completion.

The foreground agent command uses `env_clear` and an explicit environment.
`GITHUB_TOKEN`, `GH_TOKEN`, `AGENT_DIRECTOR_TOKEN`, Git credential configuration
and Actions command-file channels are absent. The agent commits its work; a
later workflow step pushes and reports. Private `HOME`, `CARGO_HOME` and
`RUSTUP_HOME` are hygiene on a disposable runner, not a security boundary.
There is no separate agent account or UID hand-over/retirement protocol.
The foreground process group is killed on completion or timeout; disposal owns
any detached descendants.

## H1 compiler isolation

The whole worker job overrides `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` and
both `CARGO_BUILD_*` wrapper forms to empty, sets `CARRICK_SCCACHE=0`, disables
sccache and clears its endpoint selection. No rust-cache action runs. The
restore-only toolchain archive remains, after the driver build. The first
worker step refuses admission if the runner UID owns an sccache process or the
process census fails; it never contacts that service. Templates must not
prestart one.

Rust homes are physical private copies. Both Cargo home configuration files
(`config` and `config.toml`), including symlinks and their `[env]` entries, are
excluded. The agent command sets both Rust wrappers explicitly empty and
`CARRICK_SCCACHE=0` and inherits no `SCCACHE_*` variables. The unchanged H1
witness plants a marker-writing wrapper in each Cargo config filename, runs
real Cargo against a dependency-free fixture, and checks successful compilation,
absence of the marker, and absence of runner endpoint variables. The workflow
witness exercises runner-UID admission for present, absent and failed censuses.

## Branches, reporting and artifacts

A fresh job uses only `work/dispatch-<issue>-<run_id>`, derived from the admitted
issue and Actions run ID. Completion refuses a different current branch and
pushes only `HEAD:refs/heads/<assigned branch>`, with an explicit tip lease,
without tags or submodules. A fresh branch must be absent remotely.
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

Host-portable tests exercise the real agent-command construction and completion
with a fixture launcher and local Git/GitHub stand-ins. They do not establish
live deployed acceptance. The post-landing default-branch trigger and fresh-clone
trials remain with the director under #634.
