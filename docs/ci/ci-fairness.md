# Releasing Hosted CI capacity

Closed PRs and runs already blocked by a named main defect should not occupy
`carrick-macos-ci` while the fix waits. The director applies
`scripts/ci/patches/1628-ci-fairness.patch` with `git apply`, then deletes the
patch. It adds one observer workflow, leaving Hosted CI's existing supersession
concurrency unchanged. Install the observer on the default branch before testing
it: `repository_dispatch` only triggers workflows present there.

The one-shot classifier uses an Ubuntu hosted runner and a concurrency group
keyed by run and job ID
with `cancel-in-progress: false`; closure events have a separate PR key.
The job subkey prevents simultaneous distinct failures from replacing a pending
invocation. Duplicate deliveries of the same job may coalesce safely. It runs
only default-branch xtask code, never a PR checkout, artifact or executable.
`pull_request_target: closed` is intentional: ordinary `pull_request: closed`
has a read-only token for forks, so cannot cancel their runs. The target event
uses only the numeric PR identity, rechecks that it is still closed, and cancels
active runs of `.github/workflows/ci.yml` whose event is `pull_request` and whose
API PR association matches. It cannot cancel merge groups, other workflows or
unassociated runs. It enumerates active statuses with pagination rather than
scanning historical runs. No branch-name comparison is used for fork identity.

GitHub does **not** support `workflow_job` as an Actions workflow trigger.
A trusted webhook relay must forward only `workflow_job` events whose action is
`completed` and conclusion is `failure` as `repository_dispatch` with event type
`ci-job-failed` and the original payload as `client_payload`. The relay must
verify GitHub's webhook signature and repository identity before forwarding;
its App needs Contents write for dispatch. That separate credential is never
provided to this workflow (which has only Actions write and read permissions).
Provisioning this relay is a director deployment prerequisite, not implemented
by this patch. Do not claim the watcher is live until delivery is witnessed.

Each invocation classifies exactly the triggering job and exits, with no sleeps,
polling or long-lived observer. It rechecks the run's workflow/event and current
attempt membership through GitHub, rejecting stale events from older attempts.
While a self-hosted macOS job remains queued or running, it compares that job's
log against current open `main-defect` issues.
All Hosted CI jobs except `cache-warm` feed `ci-ok`; the cache publisher is
excluded. Each issue must contain a separate line such as:

```
Failing test: `module::test_name`
```

Only an exact Cargo/libtest `test module::test_name ... FAILED` record matches.
Actions timestamps and Cargo colors are handled; mentions, partial names,
passing tests, closed issues and issues without the label never authorize
cancellation. Multiple `Failing test:` lines are allowed. This first contract
does not classify compiler errors, nextest summaries, timeouts or panics without
a libtest failure record. Those runs continue normally. API or parse errors
fail the observer visibly rather than authorizing cancellation.

Before cancelling, the observer writes a summary with the failing test and issue
link. GitHub exposes run cancellation, not individual job cancellation: the
entire doomed Hosted CI run is cancelled, which releases its remaining macOS
jobs and preserves the completed failure logs. It never turns that failure into
a green check. Jobs using `always()` can finish their short cleanup/gate work.
The classifier occupies a hosted Linux slot for one API pass, with a five-minute
workflow safety bound; it never consumes a Mac slot. Compilation may dominate
startup time; there is no promise of seconds from delivery on a cold runner.

## Giving the fix capacity

A `main-defect-fix` PR label does **not** give a GitHub Actions job priority.
GitHub's runner routing uses runner groups and labels, not PR labels, and there
is no supported API to reorder an existing runner queue. Declaring the label
alone would promise scheduling behavior that does not exist.

The closest immediate alternative is the cancellation above: it frees capacity
for the fix without preempting viable PRs. If guaranteed reserved capacity is
needed, the director can provision a separate runner with a dedicated label
(e.g. `carrick-macos-fix`) and route labelled PRs to it. Ordinary jobs must not
include that label, and the dedicated runner must not carry `carrick-macos-ci`,
otherwise ordinary queued jobs can consume it. This requires real extra runner
capacity and a director-owned workflow/routing change; this patch does not
invent a label on the existing three runners or claim queue priority.

GitHub documents [concurrency queues](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency),
[workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows),
[run cancellation](https://docs.github.com/en/rest/actions/workflow-runs#cancel-a-workflow-run)
and [self-hosted routing](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/use-in-a-workflow).

## Director live witness

After installation, close a disposable PR with queued and running Hosted CI
runs, then check that both are cancelled and an unrelated PR and merge group
continue. Reopen the PR and verify a delayed closure cannot cancel its new run.
For the defect case, use an open labelled issue naming a deliberately failing
test in a required job, with macOS work still outstanding; verify the observer
summary links it and cancels that run. Repeat with a partial name and a closed
issue to confirm those runs continue. This exercises GitHub permissions,
event delivery, log availability and runner release, which local fixtures
cannot prove. The worker runner has no GitHub token and cannot perform this
live acceptance or publish the independent review.
