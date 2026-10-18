# Issue-label worker dispatch (#634)

An owner issue-label event runs a foreground agent, preserves its branch,
opens a draft PR with `Closes #N` or comments on an existing PR, and posts the structured
contract on the issue. No director session is involved. Implementation lives
in `xtask dispatch-worker` and `xtask agent-runner`; the workflow only wires
Actions credentials, caches and lifecycle steps.

## Labels and brief

The checked-in [tier allowlist](../../.github/dispatch-tiers.toml) is exact:

| Label | Backend | Model | Effort |
|---|---|---|---|
| `dispatch:sol-high` | codex | gpt-6.1-sol | high |
| `dispatch:argon-high` | agy | argon-high | backend default |
| `dispatch:opus` | agy | opus | backend default |

Only `tjfontaine`, with account type `User`, may label or rerun dispatches.
The issue author must also be `tjfontaine`. The worker App and every other
identity are refused, so a token held by an agent cannot admit another run.
The hosted guard validates repository, owner identity/type, issue author, label and brief
before requesting a worker. The worker repeats validation. Unknown labels or
other actors fail closed. The Contabo controller independently verifies the
trusted main workflow, both actors and the completed successful guard job on
the current run attempt before reserving a clone or accepting reassignment.

An issue needs a nonempty `## Brief` section. It ends at the next level-one or
level-two heading outside code fences. For example:

```markdown
## Brief
Fix the documented scheduler contract. Include the red witness and focused tests.
```

A single explicit `Branch: work/dispatch-123-fix` line outside code fences
resumes a remote branch and rebases it onto freshly fetched GitHub main.
It may select only `work/dispatch-<issue>-*`, or a same-repository branch whose
open PR references this issue. Other branches are refused before agent execution.
Otherwise the worker creates `work/dispatch-<issue>-<title-slug>` and refuses an
already existing remote branch. Issue text never becomes shell source.
Each issue's labels serialize; pool capacity is enforced by the controller.

## Runner-independent setup and protected credentials

The job requires only the `carrick-agent` label, independent of runner provider.
A standard Linux or macOS Actions runner needs git, gh, curl and Python 3.
The workflow installs the pinned Rust toolchain and builds its trusted driver
before any cache restore. It copies that driver outside the restored target.
Toolchain and Cargo caches are restore-only: no post-agent cache save runs,
and cached Cargo executables are not restored. The agent receives physical,
writable copies of Cargo/Rustup homes and a private PATH; changes to those
copies are never reused by credentialed steps or saved as caches.
`agent-runner bootstrap` installs codex, agy and just from the checked-in
[tool manifest](../../scripts/ci/inputs/agent-tools.json). Versioned URLs and
SHA-256/SHA-512 digests are verified before extracting only the named regular
binary. AGY auto-update is disabled. The private `carrick-sh/agy-director`
launcher is fetched at the manifest's exact commit, never floating main.
Its `dispatch --foreground --result-file` path owns, waits for and reaps the
worker using the same backend/model/SDK resolution as director dispatch.
The foreground launcher disables mailbox instructions.

Configure protected environment **`agent-dispatch`** to allow **main only**.
It is entered only after the owner-only guard. Required environment secrets:

| Secret | Purpose |
|---|---|
| `AGENT_DIRECTOR_TOKEN` | Short-lived installation token for agy-director, contents:read |
| `AGENT_WORKER_TOKEN` | Short-lived installation token for carrick, contents/issues/pull_requests:write |
| `CODEX_AUTH_JSON` | Raw contents of the owner's refreshed ~/.codex/auth.json |
| `AGY_OAUTH_TOKEN` | Raw contents of ~/.gemini/antigravity-cli/antigravity-oauth-token |

The App private key stays on the Mac. It must never be a GitHub secret or
reach a runner. The workflow does not mint installation tokens. The Mac's
`sh.carrick.agent-secrets` launchd job mints and publishes these two narrowly
scoped, one-hour tokens every 15 minutes, giving a new job at least 45 minutes
of token life. Bootstrap receives `AGENT_DIRECTOR_TOKEN` as `GH_TOKEN` only
for the private launcher checkout; worker execution and PR publication receive
`AGENT_WORKER_TOKEN` as `GH_TOKEN`.

AGY receives only its raw OAuth token file at
`~/.gemini/antigravity-cli/antigravity-oauth-token` in the isolated job home.
No JSON file bundle, jetski state or installation ID is required.
Only the selected backend's files are materialized. The job-scoped home has
mode 0700; auth files have mode 0600 and cannot overwrite an existing file.
Codex uses file credential storage in that home. Agent auth, provider logs,
private checkout and writable SDK caches live under the job's `RUNNER_TEMP`
state, outside Cargo caches and uploaded artifacts. The always-run cleanup
removes the entire state. Runner cancellation still depends on Actions running
cleanup; the Contabo provider also destroys its one-job VM.

The **whole worker job is capped at 40 minutes**, including checkout, toolchain
setup, driver build, bootstrap, execution, publication and cleanup. The run
step is also capped at 40 minutes. The first step stamps the job start time;
setup time is deducted from the nominal 30-minute agent turn, its outer
custody deadline is minute 32, and authenticated publication stops by minute
39. This leaves margin against the 45-minute minimum token lifetime. Slow
setup shortens the turn or fails as host/infra rather than starting a fresh
30-minute budget after setup.

Bootstrap and worker startup validate their token against the target repository.
Rejected/expired tokens and unavailable GitHub access fail with a **host/infra**
message naming the affected secret and the Mac refresher. Remote command
failures recheck token access for the same diagnosis. A rejected worker token
cannot publish its own issue comment; the local result and recovery artifacts
remain available when validation succeeds. Credential-bearing outputs are
refused by the publication gate below; clone credentials are not synced back
to the owner.

The source of truth is the owner's Mac login state. The owner signs into
codex/agy there; its launchd refresher refreshes locally and pushes updated
protected secrets. Shared refresh-token collisions are an owner-accepted
risk: refresh then push on the Mac, bound jobs, and never sync clone state
back. This supersedes the original requirement to log into template VM 9000;
job setup does not depend on baked template credentials. See the
[owner decision](https://github.com/carrick-sh/carrick/issues/634#issuecomment-6252166307).
Python launcher code stays in the private repo, not in Carrick.

## Work, results and recovery

The agent runs in a fresh worktree under a shared local `carrick` build lease.
On Contabo, leases are per VM under
[owner decision #639](https://github.com/carrick-sh/carrick/issues/639).
The controller holds no physical-host custody. Other configured hosts retain
their own HostLease selection; a broker is used only when configured.

The JSON contract contains `status` (`done`, `blocked`, `failed`), `summary`,
`tests` and `risks`. The issue comment also records the actual branch, SHA,
draft PR, transport exit/timeout and publication errors. A completed work
contract does not hide transport failure. Uncommitted changes become a WIP
commit with the tier's vendor noreply trailer, including on timeout/failure.
Hooks remain enabled; checkpoint failure is reported, not bypassed. The agent
runs in an owned process group; timeout cancellation and normal completion
kill any group members left behind before output validation begins.

Every workflow publication passes one redaction gate: WIP staging/commit,
push, commit history, staged and working files, binary patch/bundle, contract
fields (before JSON escaping), PR bodies, comments, and every result artifact. Before the agent runs,
the driver captures credential values from the job, materialized provider files
and previous credentialed steps; refreshed provider credentials are added after
the run. Exact credential values and generic GitHub token, JWT and
`refresh_token` markers cause publication to be refused. The contract becomes
a redacted failure and the unsafe artifacts are discarded. The gate rejects
symlinks and paths outside the admitted repository shape, generated tracked
paths, files/objects over 1 MiB, more than 256 commits or 4,096 new objects,
and more than 20 MiB of source objects or result artifacts. The fetched base
SHA and expected push tip are captured before execution; mutable refs,
replacement objects, grafts and a redirected Git worktree cannot change the
validation view. Recovery refuses a different current branch, and push disables
implicit annotated-tag publication. Unknown or unreadable outputs
fail closed. These checks can also refuse legitimate token examples.

Actions uploads only a fresh snapshot created after validation, with its path
emitted by the trusted driver. An interrupted validation emits no artifact
path, so the always-run upload cannot sweep raw workspace outputs. Agent
children do not inherit Actions output/env/path/summary write channels.
Failed external commands retain at most 16 KiB of redacted stderr in receipts;
a truncated trailing line is discarded so a partial credential cannot escape.

Bootstrap/auth failures are reported with the same trusted driver without
starting unverified tools. A driver-build or App-token failure is visible in
Actions logs; it cannot publish a contract without a working driver/token.

The publisher pushes with an exact expected remote tip and creates a new
same-repository draft PR using the PR template and `Closes #N`. An existing PR
receives a contract comment; its body and draft/ready state are preserved.
No-change runs do not fabricate a PR. Validated `dispatch-result` output retains the contract,
receipt, issue comment, branch bundle and binary patch, allowing recovery when
push fails. Provider logs and credentials are excluded. Preserve this artifact
before retrying; resume via an explicit branch directive. A dispatch whose
result cannot be published exits nonzero rather than claiming success.

## Contabo provider and retirement

The existing standing ci-scaler controller services the `carrick-agent` lane;
there is no second controller. It clones template **9000**, with **8 vCPU /
20 GiB**, capped at **four active agent clones** independently of KVM capacity.
It retains the existing resource/headroom checks, durable ledger, restricted
VMID pool, JIT one-job runners, assignment checks, recovery and cleanup.
`CARRICK_AGENT_CLONES=0` stops new agent admission while existing clones drain.
VM 9000 remains protected in every controller mode, including with agent clones
disabled. Only source-template `VM.Audit`/`VM.Clone` privileges are allowed;
power, configuration, deletion and other mutating privileges are refused.
The provider's template needs runner/SSH plumbing and these ordinary runner
prerequisites, not provider login credentials. Install this rollout's agent-aware
xtask at `/usr/local/bin/carrick-xtask` in VM 9000: the controller refuses old
binaries before minting a JIT runner. This provider admission hook is separate
from the runner-independent workflow bootstrap. The owner deploys controller,
App/environment settings and template changes, then performs the live trial.

Retire ctb-w1..w4 only after **three successful end-to-end draft PRs** from
fresh clones. Record all three issue numbers, workflow runs, clone IDs,
contract comments, branch SHAs, draft PRs and destruction evidence on #634.
Exercise both backends and failure/WIP cleanup before claiming operational
acceptance. Drain outstanding work, archive/push each old worker's branches,
remove its runner registration and credentials, then have the owner shut down
and destroy those VMs. Workers must not modify other VMs or the hypervisor.
