# Issue-label dispatch (#634)

An owner-authored issue with a nonempty `## Brief` and an allowlisted
[`dispatch:<tier>`](../../.github/dispatch-tiers.toml) starts a foreground agent.
Only `tjfontaine`, account type `User`, may label/rerun. Guard, driver and
controller independently check admission; the worker App cannot admit work.
Issues serialize; the controller destroys each one-job clone afterwards.

The agent has **no GitHub publish credential**. Its job never receives
`AGENT_WORKER_TOKEN`; its cleared environment has no `GH_TOKEN`, GitHub token
or Actions command-file channels, and its HOME has no credential helper.
Bootstrap's launcher-read token stays with the runner. Linux clones need git,
gh, curl, Python 3 and runner sudo for a separate account without login,
password, sudo rights or runner membership. A runner-held shared lease covers
execution; Contabo leases stay VM-local (#639). Tools/launcher are
[digest-pinned](../../scripts/ci/inputs/agent-tools.json). Checkout uses admitted
`github.sha`. The driver builds before restore-only caches; agent Rust homes
are physical private copies and are never saved.

Before packaging, the driver stops/kills every process with the agent's real
or effective UID, including detached sessions, reaps adopted children and
refuses if any remain. It retires the account, then copies regular files into
a private runner-owned snapshot, discarding candidate Git config, hooks,
index, alternates and refs. All driver Git commands disable hooks, fsmonitor,
external configuration and filters. Only this immutable snapshot is checkpointed.
Always-run cleanup repeats retirement and removes provider/launcher state.

Upload uses fixed `$RUNNER_TEMP/dispatch-output`: result/contract JSON,
bounded redacted logs and a single-ref bundle when commits changed. The upload
action's numeric artifact ID passes to a **fresh hosted Ubuntu publisher**,
the only job holding `AGENT_WORKER_TOKEN`. It builds trusted main code without
caches **before** downloading by ID, never name. It executes no candidate code.
Receipt/event/base identity, exact prerequisite/ref, every commit's descent
from base (including merge sides) and the entire imported object population
are checked. Tags/extra refs or objects, links and generated tracked paths
are refused. Caps: 20 MiB compressed/decoded, 1 MiB/object, 256 commits,
4,096 objects. Every new blob/tree, commit message, uploaded file, raw contract
field and comment/PR body passes the credential gate; stderr stays redacted.

**Encoding evasion is a non-goal of matching.** The credential boundary
defends publication: the agent cannot publish directly; only the publisher
publishes validated content. Matching does not detect arbitrary encodings.
Provider credentials remain available for the authorized turn.

Fresh branches are only `work/dispatch-<issue>-<run_id>`, with collision refusal.
`Branch: work/...` outside HTML comments/fences requests continuation, requiring
an open same-repository App-created PR and an exact App-authored ownership
comment for this issue/branch. Prefixes or PR bodies mentioning `#N` grant no
ownership. The recorded remote tip must still match; push uses only
`HEAD:refs/heads/<owned branch>`, without tags/hooks. New work creates a
template-based draft PR and marker; existing PR bodies/states are preserved.

Protect **agent-dispatch** to main. The Mac `sh.carrick.agent-secrets` refresher
supplies launcher-read, publisher-write and selected provider credentials;
the App key stays on the Mac and clone refresh state never flows back.
Provider files stay 0600 in a 0700 home. Setup reduces the 30-minute turn
within the 40-minute job; publisher credentials arrive separately.
Artifacts retain 30 days. Template **9000** stays source-only/protected, with
at most four 8-vCPU/20-GiB clones. See [rollout](contabo-kvm.md) and #634:
the owner records three fresh-clone PR trials, both backends and WIP/cleanup,
before retiring ctb-w1..w4. Linux checks do not replace signed/live acceptance.
