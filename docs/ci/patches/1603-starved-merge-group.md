# Starved merge-group jobs: diagnostic slice, retry blocked

This is **not the completed retry fix** for #1603. The accompanying patch
adds cancellation diagnostics to the existing `ci-ok` path and preserves
`just ci-results` as its sole verdict. It leaves hosted macOS checks hosted.
Do not use this slice as evidence that merge-queue ejection is fixed.

## Why the requested retry cannot run inside ci-ok

[GitHub's job rerun endpoint](https://docs.github.com/en/rest/actions/workflow-runs#re-run-a-job-from-a-workflow-run)
reruns the job and its dependent jobs, including `ci-ok`. It requires Actions
write permission. More importantly, a containing workflow that is still
running cannot be rerun: a [first-person API report](https://github.com/orgs/community/discussions/210668)
records HTTP 403, “The workflow run containing this job is already running”.
Waiting in `ci-ok` keeps that workflow running, so the retry cannot begin.
No mutating API request was made during this investigation.

A completed-run recovery controller avoids that deadlock, but an initial red
`ci-ok` may already eject the merge group. Preserving queue membership needs
an agreed change to the check lifecycle, such as an externally owned pending
aggregate check. That is beyond a retry inside the current aggregation path.
The next design must also bound retries across attempts and serialize multiple
job reruns, since the first accepted rerun makes the workflow active again.

## Historical dry run

The unmodified full REST jobs response for run `41865736523` contains 29 jobs.
The GitHub connector's jobs wrapper omits assignment fields; the full REST
response was read instead. Both cancelled jobs have `runner_name: ""`,
`runner_id: 0`, and `steps: []`:

| Job | Job ID | Created | Completed | Queue interval |
|---|---|---|---|---|
| macos-clippy | 126701119636 | 16:20:39Z | 16:40:08Z | 19m 29s |
| macos-authority | 126701120224 | 16:20:39Z | 16:45:08Z | 24m 29s |

Their job-level `started_at` equals `created_at` despite no runner assignment;
that timestamp alone is **not** evidence of execution. Classification requires
an explicitly empty runner name and no started steps. Missing assignment or
step metadata fails closed. A failed job is never retry-eligible.

Reproduce without changing any run:

```sh
gh api 'repos/carrick-sh/carrick/actions/runs/41865736523/jobs?per_page=100' > jobs.json
just xtask ci-starved-jobs --jobs jobs.json
```

The tool refuses an incomplete page. It reports both macOS jobs retry-eligible
and the incident's failed `ci-ok` as fail. Eligibility is diagnostic only; it
neither schedules a retry nor excuses a failed dependency.

## Independent Sol review

A fresh GPT-6.1 Sol reviewer checked the revised diagnostic slice and patch.
No outstanding P0, P1, or P2 findings remained. Initial observations about
optional diagnostics interfering with the verdict and missing public CLI
coverage were addressed: diagnostic steps tolerate errors, query the current
attempt explicitly, and the CLI witness covers all three requested
classifications plus incomplete-response rejection. The reviewer independently
identified the active-workflow rerun limitation above as blocking retry
acceptance. This review was retained locally for the publishing workflow;
no PR review or comment was posted by the worker.
