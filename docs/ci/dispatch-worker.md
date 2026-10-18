# Issue-label dispatch (#634)

Only the owner, account type `User`, may label/rerun an owner-authored issue.
Guard, driver and controller enforce admission and the checked-in tier allowlist.
The Linux clone runs the agent as a separate system user without login or sudo.
The driver builds before restore-only caches; Rust homes are physical private
copies. Checkout uses admitted `github.sha`; tools/launcher remain digest-pinned.

The agent has **no GitHub publish credential**, inherited token environment,
Actions command-file channels or Git credential helper. Bootstrap's read token
stays with the runner. Before packaging, every process with the agent's real
or effective UID is killed, detached children are reaped and absence verified.
The account is retired; a private runner-owned copy discards candidate Git
config, hooks, index, alternates and refs. All driver Git commands disable hooks,
fsmonitor, external configuration and filters. Cleanup repeats retirement.

Upload uses fixed `$RUNNER_TEMP/dispatch-output`: result/contract JSON, redacted
logs and a single-ref bundle. Its artifact ID passes to a fresh hosted publisher,
the **only job holding the write token**. It builds trusted main code without
caches before downloading by ID, never name, and executes no candidate code.
It validates event/base identity, exact prerequisite/ref, every commit's descent
from base (including merge sides) and the complete imported object population.
Tags/extra refs or objects, links and generated paths are refused. Caps: 20 MiB,
1 MiB/object, 256 commits, 4,096 objects. Every new blob/tree, commit message,
uploaded file, raw contract field and comment/PR body passes the credential gate.

**Encoding evasion is a matching non-goal.** The credential boundary defends
publication: the agent cannot publish directly; only validated content is
published by the publisher. Matching does not detect arbitrary encodings.

Fresh branches are `work/dispatch-<issue>-<run_id>`, with collision refusal.
`Branch:` outside HTML comments/fences requests continuation: an open App-created
same-repository PR and exact App-authored issue/branch marker are required.
Prefixes and PR bodies mentioning `#N` grant no ownership. The recorded tip must
still match. Push uses only `HEAD:refs/heads/<owned branch>`, without tags/hooks.
New PRs use the template; existing bodies/states are preserved.

Protect both environments to main. **agent-execution** holds only
`AGENT_DIRECTOR_TOKEN`, `CODEX_AUTH_JSON` and `AGY_OAUTH_TOKEN`;
**agent-dispatch** is publisher-only and holds `AGENT_WORKER_TOKEN` plus provider
values for redaction. Update the Mac refresher to populate execution's read/
provider secrets, never its write token; the App key stays on the Mac.
Provider files stay 0600 in a 0700 home; refresh state never flows back.
The worker cap stays 40 minutes; artifacts retain 30 days. VM-local leases,
protected template 9000 and the three fresh-clone rollout trials remain as
documented in [Contabo setup](contabo-kvm.md) and #634; signed/live acceptance
remains with the director.
